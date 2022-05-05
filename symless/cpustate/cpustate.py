import copy
import ctypes

import idaapi
import idautils

import symless.cpustate.arch as arch
import symless.ida_utils as ida_utils
from symless.cpustate import *

# max functions depth to propagate a structure
MAX_PROPAGATION_RECURSION = 100


# get instructions operands + convert registers (al -> rax)
def get_insn_ops(insn: idaapi.insn_t) -> list:
    ops = list()
    for op in insn.ops:
        if op.type != idaapi.o_void:
            if op.reg in X64_REG_ALIASES:
                op.reg = X64_REG_ALIASES[op.reg]
            ops.append(op)
    return ops


# ignore instruction
def handle_ignore(state: state_t, *args):
    pass


# drop one reg values when we do no know its new value
def handle_reg_drop(state: state_t, insn: idaapi.insn_t, op: idaapi.op_t):
    if op.type == idaapi.o_reg:
        state.drop_register(op.reg)


def handle_mov_reg_reg(state: state_t, insn: idaapi.insn_t, dst: idaapi.op_t, src: idaapi.op_t):
    cur = state.get_register(src.reg)
    state.set_register(dst.reg, cur)


def handle_mov_disp_reg(state: state_t, insn: idaapi.insn_t, dst: idaapi.op_t, src: idaapi.op_t):
    # mov [rax+rbx*2+n]
    # ignore basereg + indexreg*scale + offset cases
    if x64_index_reg(insn, dst) != x86_INDEX_NONE:
        # FIXME: stack value may be replaced here and we won't know
        return

    base = x64_base_reg(insn, dst)
    cur = state.get_register(src.reg)
    nex = state.get_register(base)
    nbytes = idaapi.get_dtype_size(dst.dtype)

    if isinstance(nex, stack_ptr_t):
        shift = ctypes.c_int32(dst.addr + nex.shift).value
        state.stack.push(shift, cur)
    else:
        # do not report src to be used when pushed in stack
        state.arguments.validate(cur)

        disp = disp_t(base, dst.addr, nbytes)
        state.write_to(insn.ea, disp, cur)


def handle_mov_reg_imm(state: state_t, insn: idaapi.insn_t, dst: idaapi.op_t, src: idaapi.op_t):
    nbytes = idaapi.get_dtype_size(dst.dtype)
    state.set_register(dst.reg, int_t(src.value, nbytes))


def handle_mov_disp_imm(state: state_t, insn: idaapi.insn_t, dst: idaapi.op_t, src: idaapi.op_t):
    # FIXME: mov [rsp + rcx*2 + 16], 200h will modify the stack
    # without us unvalidating the old value
    if x64_index_reg(insn, dst) != x86_INDEX_NONE:
        return

    base = x64_base_reg(insn, dst)
    cur = state.get_register(base)
    nbytes = idaapi.get_dtype_size(src.dtype)

    if isinstance(cur, stack_ptr_t):
        shift = ctypes.c_int32(dst.addr + cur.shift).value
        state.stack.push(shift, int_t(src.value, nbytes))

    else:
        # special win32 vtable load case
        # mov [ecx], offset vftable
        # to simplify vtable detection, consider immediate to be a mem_t

        disp = disp_t(base, dst.addr, nbytes)
        state.write_to(insn.ea, disp, mem_t(src.value, src.value, nbytes))


def handle_mov_reg_mem(state: state_t, insn: idaapi.insn_t, dst: idaapi.op_t, src: idaapi.op_t):
    nbytes = idaapi.get_dtype_size(dst.dtype)
    value = ida_utils.get_nb_bytes(src.addr, nbytes)
    if value is not None:
        state.set_register(dst.reg, mem_t(value, src.addr, nbytes))
    else:  # register loaded with bss data
        state.drop_register(dst.reg)


def handle_mov_reg_disp(state: state_t, insn: idaapi.insn_t, dst: idaapi.op_t, src: idaapi.op_t):
    base = x64_base_reg(insn, src)
    cur = state.get_register(base)

    # mov rbx, [rax+rcx*2+n], ignored
    if x64_index_reg(insn, src) != x86_INDEX_NONE:
        state.drop_register(dst.reg)
        return

    # mov rax, [rsp+0x10]
    if isinstance(cur, stack_ptr_t):
        shift = ctypes.c_int32(src.addr + cur.shift).value
        value = state.stack.pop(shift)
        if value is not None:
            state.set_register(dst.reg, value)
            return

    nbytes = idaapi.get_dtype_size(dst.dtype)

    # PIE memory move: mov rdx, [rax + vtbl_offset]
    dref = idaapi.get_first_dref_from(insn.ea)
    if dref != idaapi.BADADDR:
        value = ida_utils.get_nb_bytes(dref, nbytes)
        if value is not None:
            state.set_register(dst.reg, mem_t(value, dref, nbytes))
            return

    # other cases
    disp = disp_t(base, src.addr, nbytes)
    state.set_register(dst.reg, disp)

    state.read_from(insn.ea, disp, dst.reg)


def handle_call(state: state_t, insn: idaapi.insn_t, op: idaapi.op_t):
    state.call_type = call_type_t.CALL


def handle_jump(state: state_t, insn: idaapi.insn_t, op: idaapi.op_t):
    state.call_type = call_type_t.JUMP


def handle_lea_reg_mem(state: state_t, insn: idaapi.insn_t, dst: idaapi.op_t, src: idaapi.op_t):
    # avoid 'lea esi, ds:2[rax*2]' flagged as 'lea reg, mem'
    if src.specflag1:  # hasSIB
        state.drop_register(dst.reg)
    else:
        state.set_register(dst.reg, mem_t(src.addr, src.addr, ida_utils.get_ptr_size()))


def handle_lea_reg_disp(state: state_t, insn: idaapi.insn_t, dst: idaapi.op_t, src: idaapi.op_t):
    base = x64_base_reg(insn, src)
    cur = state.get_register(base)

    # mov rbx, [rax+rcx*2+n], ignored
    if x64_index_reg(insn, src) != x86_INDEX_NONE:
        state.drop_register(dst.reg)
        return

    # apply offset shift instead if input operand is a sid
    if isinstance(cur, buff_t):
        state.set_register(dst.reg, cur.offset(src.addr))
    else:
        # data can be referenced from reg disp in PIE
        # check if we have a data ref on the insn
        dref = idaapi.get_first_dref_from(insn.ea)
        if dref != idaapi.BADADDR:
            state.set_register(dst.reg, mem_t(dref, dref, ida_utils.get_ptr_size()))
        else:
            # we don't have any use for this
            state.drop_register(dst.reg)


def handle_add_reg_imm(state: state_t, insn: idaapi.insn_t, dst: idaapi.op_t, src: idaapi.op_t):
    cur = state.get_register(dst.reg)
    if not cur:
        return

    state.arguments.validate(cur)

    if not isinstance(cur, buff_t):
        state.drop_register(dst.reg)
        return

    if insn.itype == idaapi.NN_add:
        shift = src.value
    else:
        shift = -src.value
    state.set_register(dst.reg, cur.offset(shift))


def handle_xor_reg_reg(state: state_t, insn: idaapi.insn_t, dst: idaapi.op_t, src: idaapi.op_t):
    if dst.reg == src.reg:
        state.set_register(dst.reg, int_t(0, ida_utils.get_ptr_size()))
    else:
        state.drop_register(dst.reg)


# handle stack alignements
def handle_and_reg_imm(state: state_t, insn: idaapi.insn_t, dst: idaapi.op_t, src: idaapi.op_t):
    cur = state.get_register(dst.reg)
    if isinstance(cur, buff_t):
        value = ctypes.c_int32(cur.shift & src.value).value
        state.set_register(dst.reg, cur.clone(value))
    else:
        state.drop_register(dst.reg)


# stack shift by a push/pop operation
def handle_stack_shift(state: state_t, op: idaapi.op_t, is_push: bool) -> stack_ptr_t:
    size = idaapi.get_dtype_size(op.dtype)
    stack_ptr = get_stack_ptr(state)
    if not isinstance(stack_ptr, stack_ptr_t):
        return None

    if is_push:
        size = -size

    stack_ptr = stack_ptr.offset(size)
    set_stack_ptr(state, stack_ptr)
    return stack_ptr


def handle_push_reg(state: state_t, insn: idaapi.insn_t, op: idaapi.op_t):
    stack_ptr = handle_stack_shift(state, op, True)
    reg = state.get_register(op.reg)
    if stack_ptr is not None and reg is not None:
        state.stack.push(stack_ptr.shift, reg)


def handle_push_imm(state: state_t, insn: idaapi.insn_t, op: idaapi.op_t):
    stack_ptr = handle_stack_shift(state, op, True)
    if stack_ptr is not None:
        nbytes = idaapi.get_dtype_size(op.dtype)
        state.stack.push(stack_ptr.shift, int_t(op.value, nbytes))


def handle_pop_reg(state: state_t, insn: idaapi.insn_t, op: idaapi.op_t):
    # drop dst reg in any case
    state.drop_register(op.reg)

    stack_ptr = get_stack_ptr(state)
    if isinstance(stack_ptr, stack_ptr_t):

        # record poped value
        value = state.stack.pop(stack_ptr.shift)
        if value is not None:
            state.set_register(op.reg, value)

        # shift stack ptr
        size = idaapi.get_dtype_size(op.dtype)
        set_stack_ptr(state, stack_ptr.offset(size))


# shift stack pointer, ignore pushed/poped value
def handle_ignored_push_pop(state: state_t, insn: idaapi.insn_t, op: idaapi.op_t):
    handle_stack_shift(state, op, (insn.itype == idaapi.NN_push))


# validate register operand to be a used argument, to keep track of function args count
# other type of operands (displ, phrase) are already validated in process_instruction()
def validate_operand(state: state_t, insn: idaapi.insn_t, op: idaapi.op_t):
    if op.type == idaapi.o_reg:
        state.arguments.validate(state.get_previous_register(op.reg))


# handle test instruction
def handle_test(state: state_t, insn: idaapi.insn_t, op1: idaapi.op_t, op2: idaapi.op_t):
    validate_operand(state, insn, op1)
    validate_operand(state, insn, op2)


# instructions specific handlers
# list of (list[insn.itype], tuple(ops.type), handler)
g_insn_handlers = [
    (
        # 1 operand instructions
        ([idaapi.NN_push], (idaapi.o_reg,), handle_push_reg),  # push rbp
        ([idaapi.NN_push], (idaapi.o_imm,), handle_push_imm),  # push 42h
        ([idaapi.NN_push], (idaapi.o_displ,), handle_ignored_push_pop),  # push [ebp+var_14]
        ([idaapi.NN_push], (idaapi.o_mem,), handle_ignored_push_pop),  # push bss_var
        ([idaapi.NN_push], (idaapi.o_phrase,), handle_ignored_push_pop),  # push dword[rcx]
        ([idaapi.NN_pop], (idaapi.o_reg,), handle_pop_reg),  # pop rbp
        ([idaapi.NN_pop], (idaapi.o_displ,), handle_ignored_push_pop),  # pop [rbp+var_14]
        ([idaapi.NN_pop], (idaapi.o_phrase,), handle_ignored_push_pop),  # pop [rcx]
        ([idaapi.NN_pop], (idaapi.o_mem,), handle_ignored_push_pop),  # pop data_var
        (INSN_CALLS, (0,), handle_call),  # call ?
        (INSN_JUMPS, (0,), handle_jump),  # jne  ?
    ),
    (
        # 2 operands instructions
        (INSN_MOVES, (idaapi.o_phrase, idaapi.o_reg), handle_mov_disp_reg),  # mov [rcx], rax
        (INSN_MOVES, (idaapi.o_displ, idaapi.o_reg), handle_mov_disp_reg),  # mov [rcx+10h], rax
        (INSN_MOVES, (idaapi.o_phrase, idaapi.o_imm), handle_mov_disp_imm),  # mov [rcx], 10h
        (INSN_MOVES, (idaapi.o_displ, idaapi.o_imm), handle_mov_disp_imm),  # mov [rcx+10h], 10h
        (INSN_MOVES, (idaapi.o_reg, idaapi.o_reg), handle_mov_reg_reg),  # mov rax, rbx
        (INSN_MOVES, (idaapi.o_reg, idaapi.o_imm), handle_mov_reg_imm),  # mov rax, 10h
        (INSN_MOVES, (idaapi.o_reg, idaapi.o_mem), handle_mov_reg_mem),  # mov rax, @addr
        (INSN_MOVES, (idaapi.o_reg, idaapi.o_phrase), handle_mov_reg_disp),  # mov rax, [rbx]
        (
            INSN_MOVES,
            (idaapi.o_reg, idaapi.o_displ),
            handle_mov_reg_disp,
        ),  # mov rax, [rbx+10h]
        (INSN_MOVES, (idaapi.o_mem, 0), handle_ignore),  # mov @addr, ?
        (INSN_TESTS, (0, 0), handle_test),  # test ?, ?
        (INSN_CMPS, (0, 0), handle_test),  # cmp ?, ?
        (INSN_LEAS, (idaapi.o_reg, idaapi.o_mem), handle_lea_reg_mem),  # lea rax, @addr
        (
            INSN_LEAS,
            (idaapi.o_reg, idaapi.o_displ),
            handle_lea_reg_disp,
        ),  # lea rax, [rbx+10h]
        (INSN_LEAS, (idaapi.o_reg, 0), handle_ignore),  # lea rax, ?
        (INSN_XORS, (idaapi.o_reg, idaapi.o_reg), handle_xor_reg_reg),  # xor rax, rax
        (INSN_ANDS, (idaapi.o_reg, idaapi.o_imm), handle_and_reg_imm),  # and esp, 0xfffffff0
        (INSN_MATHS, (idaapi.o_reg, idaapi.o_imm), handle_add_reg_imm),  # add rax, 10h
    ),
]


# check wheter given insn types meet the required ones
def check_types(effective: tuple, expected: tuple) -> bool:
    for i in range(len(expected)):
        if expected[i] != 0 and effective[i] != expected[i]:
            return False
    return True


# dump insn & operands
def dump_insn(insn: idaapi.insn_t, ops):
    print(insn_str(insn))
    for op in ops:
        print("\t" + op_str(op))


# handle zero-operand instructions
def handle_no_op_insn(state: state_t, insn: idaapi.insn_t):
    if insn.itype in INSN_RETS:
        state.save_ret(insn.ea)


# handle one-operand instructions
def handle_one_op_insn(state: state_t, insn: idaapi.insn_t, ops):
    handler, it_type = None, None
    op = ops[0]

    for itype, optype, current in g_insn_handlers[0]:
        if insn.itype in itype:
            it_type = insn.itype
            if check_types((op.type,), optype):
                handler = current
                break

    if not it_type:
        handle_reg_drop(state, insn, op)
        return

    if handler:
        handler(state, insn, op)
        return

    if False:
        dump_insn(insn, ops)
        raise BaseException("not implemented")


# handle two-operands instructions
def handle_two_ops_insn(state: state_t, insn: idaapi.insn_t, ops):
    handler = None
    dst, src = ops[0], ops[1]
    known_type = None
    for itypes, optype, current in g_insn_handlers[1]:
        if insn.itype in itypes:
            known_type = insn.itype
            if check_types((dst.type, src.type), optype):
                handler = current
                break

    if not known_type:
        # drop destination register only
        handle_reg_drop(state, insn, dst)
        return

    if handler:
        handler(state, insn, dst, src)
        return

    if dst.type == idaapi.o_reg:
        state.drop_register(dst.reg)

    if False:
        dump_insn(insn, ops)
        raise BaseException("not implemented")


# process one instruction & update current state
def process_instruction(state: state_t, insn: idaapi.insn_t):
    ops = get_insn_ops(insn)
    state.reset()

    op_len = len(ops)
    if op_len == 0:
        handle_no_op_insn(state, insn)
    elif op_len == 1:
        handle_one_op_insn(state, insn, ops)
    elif op_len == 2:
        handle_two_ops_insn(state, insn, ops)
    elif op_len == 3:
        handle_reg_drop(state, insn, ops[0])
    elif op_len == 4:
        handle_reg_drop(state, insn, ops[0])
    else:
        print("unsupported instruction with %d operands:" % op_len)
        dump_insn(insn, ops)

    # register any access through displ missed by custom handlers
    for i, op in enumerate(ops):
        if op.type in [idaapi.o_phrase, idaapi.o_displ]:
            base = x64_base_reg(insn, op)
            index = x64_index_reg(insn, op)

            # validate base reg for parameters tracking
            cur = state.get_previous_register(base)
            state.arguments.validate(cur)

            if index == x86_INDEX_NONE:  # ignore base + index*scale + offset
                nbytes = idaapi.get_dtype_size(op.dtype)
                state.access_to(insn.ea, i, disp_t(base, op.addr, nbytes))
            else:  # validate index usage
                cur = state.get_previous_register(index)
                state.arguments.validate(cur)


# read all instructions from input basic block
def read_basic_block_instructions(bb: idaapi.qbasic_block_t):
    ea = bb.start_ea
    while ea < bb.end_ea:
        # skip non-code instructions
        while not idaapi.is_code(idaapi.get_flags(ea)):
            ea = idaapi.get_item_end(ea)
            if ea == idaapi.BADADDR or ea > bb.end_ea:
                return
        # decode instruction
        insn = idautils.DecodeInstruction(ea)
        yield insn
        ea += insn.size


# select most interesting state (most sid_t, call_t)
def select_state(states: list) -> state_t:
    states.sort(key=lambda e: (e.get_nb_types(sid_t), e.get_nb_types(call_t)), reverse=True)
    return states[0]


# Get the starting state for a basic block
# if many states are possible, select the one with the most info in it
def get_previous_state(flow, idx, prev_states) -> state_t:
    npred = flow.npred(idx)

    # no predecessor, just use starting state
    if npred == 0:
        if idx == 0:
            return prev_states[idaapi.BADADDR].copy()

        out = state_t()
        out.arguments = prev_states[idaapi.BADADDR].arguments  # keep arguments tracker
        return out

    # only one predecessor, use its state
    if npred == 1:
        last_node = flow.pred(idx, 0)
        if last_node == idx:
            out = state_t()
            out.arguments = prev_states[idaapi.BADADDR].arguments
            return out

        if last_node not in prev_states.keys():
            raise BaseException("invalid previous node")

        return prev_states[last_node].copy()

    # multiple predecessors, find one suitable
    predecessors = []
    for i in range(npred):
        predecessor_node = flow.pred(idx, i)
        if predecessor_node in prev_states.keys():
            predecessors.append(prev_states[predecessor_node])

    if len(predecessors) == 0:
        raise BaseException("no previous node found")

    return select_state(predecessors).copy()


def pop_node(nodes, visited):
    min_node = idaapi.BADADDR
    for node, (ea, allpreds, preds) in nodes.items():
        if len(preds) == 0:
            return node

        # if we don't find any suitable node
        # take the lower effective address
        # from those who already have a visited predecessor
        minpreds = [x for x in filter(lambda x: x in visited, allpreds)]
        if not len(minpreds):
            continue

        min_node = min(min_node, node)

    if min_node == idaapi.BADADDR:
        # raise BaseException("unexpected graph")
        # undecided, drop the remaining nodes
        return idaapi.BADADDR

    return min_node


def discard_pred(nodes, pred):
    for _, (_, _, preds) in nodes.items():
        try:
            preds.remove(pred)
        except KeyError:
            pass


def walk_topological(func, flow):
    # generate a list of nodes with predecessors
    nodes = {}
    for node in range(flow.size()):
        preds = set()
        npred = flow.npred(node)
        for j in range(npred):
            pred = flow.pred(node, j)
            # ignore cycles on the same node
            if pred != node:
                preds.add(pred)
        allpreds = copy.deepcopy(preds)
        nodes[node] = hex(flow[node].start_ea), allpreds, preds

    # iterate on nodes without known predecessors
    visited = set()
    while len(nodes):
        node = pop_node(nodes, visited)
        if node == idaapi.BADADDR:
            return

        del nodes[node]
        visited.add(node)
        discard_pred(nodes, node)
        yield node


# a visited function
class function_t:
    def __init__(self, ea):
        self.ea = ea

        # guessed cc
        self.cc = get_abi()

        # approximate count of arguments
        self.args_count = self.cc.get_arg_count()
        self.args = [set() for i in range(self.args_count)]  # sets of (sid, shift)

        self.cc_not_guessed = True

    def update_visited(self, state: state_t):
        for i in range(self.args_count):
            cur = get_argument(self.cc, state, i)
            if isinstance(cur, sid_t):
                self.args[i].add((cur.sid, cur.shift))

    def should_propagate(self, state: state_t, from_callee: bool, is_jump: bool) -> bool:
        for i in range(self.args_count):
            cur = get_argument(self.cc, state, i, from_callee, is_jump)
            if isinstance(cur, sid_t) and (cur.sid, cur.shift) not in self.args[i]:
                return True
        return False

    def has_args(self) -> bool:
        for i in range(self.args_count):
            if len(self.args[i]) > 0:
                return True
        return False

    # guess function cc & arguments count
    def guess_function_cc(self, arguments: arguments_t):

        # always use guessed cc from arguments, in case arguments'cc is de-synced with self.cc
        cc, start_arg, args_count = arguments.guess_cc()
        self.cc = cc

        fixed_args_count = min(self.cc.get_arg_count(), args_count)
        if self.cc_not_guessed:
            self.args_count = fixed_args_count

            # shift args array if needed
            if start_arg > 0:
                self.args = self.args[start_arg:]

            self.cc_not_guessed = False

        elif self.args_count < fixed_args_count:
            self.args_count = fixed_args_count

    # guessed args count
    def get_count(self) -> int:
        if self.cc_not_guessed:
            return 0
        return self.args_count


# Injector into state_t
class injector_t:
    def __init__(self, callback=None, before_update: bool = True):
        self.callback = callback  # callback(state: state_t, ea: int)
        self.before_update = before_update

    # inject before computing current instruction
    def inject_and_update(self, state: state_t, insn: idaapi.insn_t):
        self.callback(state, insn.ea)
        process_instruction(state, insn)

    # inject after computing current instruction
    def update_and_inject(self, state: state_t, insn: idaapi.insn_t):
        process_instruction(state, insn)
        self.callback(state, insn.ea)

    def update_state(self, state: state_t, insn: idaapi.insn_t):
        if self.callback is None:
            process_instruction(state, insn)
        elif self.before_update:
            self.inject_and_update(state, insn)
        else:
            self.update_and_inject(state, insn)


# States generation parameters, so caller can modify params between two yields
class propagation_param_t:
    def __init__(self, injector: injector_t = injector_t(), depth: int = MAX_PROPAGATION_RECURSION):
        self.injector = injector
        self.depth = depth
        self.visited = dict()  # ea -> function_t

    # is there a potential new state we need to visit
    def should_propagate(self, state: state_t, ea: int, from_callee: bool, is_jump: bool) -> bool:
        if self.depth == 0:
            return False

        # propagate any sid
        if ea not in self.visited:
            for i in range(get_abi().get_arg_count()):
                cur = get_argument(get_abi(), state, i, from_callee, is_jump)
                if isinstance(cur, sid_t):
                    return True

        # propagate new sid
        elif self.visited[ea].should_propagate(state, from_callee, is_jump):
            return True

        return False

    # has propagation passed by function
    def has_function(self, ea: int) -> bool:
        return ea in self.visited

    # get or create function
    def get_function(self, ea: int) -> function_t:
        if not self.has_function(ea):
            self.visited[ea] = function_t(ea)
        return self.visited[ea]

    def update_visited(self, ea: int, state: state_t) -> function_t:
        fct = self.get_function(ea)
        fct.update_visited(state)
        return fct


# Returns (should_propagate, is_call, callee_addr)
def should_propagate_in_callee(insn: idaapi.insn_t, state: state_t, params: propagation_param_t):
    is_call = insn.itype in INSN_CALLS
    if not is_call and insn.itype not in INSN_UNCONDITIONAL_JUMPS:
        return (False, False, None)

    op = insn.ops[0]
    if op.type not in [idaapi.o_mem, idaapi.o_far, idaapi.o_near]:
        return (False, is_call, op.addr)

    addr = op.addr
    if op.type == idaapi.o_mem:
        addr = ida_utils.dereference_pointer(addr)

    if not params.should_propagate(state, addr, False, not is_call):
        return (False, is_call, addr)

    # only follow function calls
    callee = idaapi.get_func(addr)
    if callee is None or callee.start_ea != addr:
        return (False, is_call, addr)

    return (True, is_call, addr)


# validate that function arguments are used if they are passed to another function
def validate_passthrough_args(caller_state: state_t, callee: function_t, is_call: bool):
    for i in range(callee.get_count()):
        cur = get_argument(callee.cc, caller_state, i, False, not is_call)
        caller_state.arguments.validate(cur)


# Propagate starting_state into func, follow calls depending on depth & visited
def function_execution_flow(
    func: idaapi.func_t, starting_state: state_t, params: propagation_param_t
):
    fct_model = params.update_visited(func.start_ea, starting_state)

    starting_state.reset_arguments(fct_model.cc)

    prev_states = dict()  # bb index -> state
    prev_states[idaapi.BADADDR] = starting_state

    flow = idaapi.qflow_chart_t()
    flow.create("", func, func.start_ea, func.end_ea, idaapi.FC_NOEXT)

    # ida default node order seems to be topological enough...
    for node in walk_topological(func, flow):
        state = get_previous_state(flow, node, prev_states)

        for insn in read_basic_block_instructions(flow[node]):

            params.injector.update_state(state, insn)

            # propagate in callee ?
            callee = None
            (propagate, is_call, callee_addr) = should_propagate_in_callee(insn, state, params)
            if callee_addr is not None:
                state.call_to = callee_addr
                if propagate:
                    callee = idaapi.get_func(callee_addr)
                elif is_call:
                    # Don't spread in callee, set call_t value in rax
                    call = call_t(callee_addr, insn.ea)
                    set_ret_value(state, call)

                    if params.has_function(callee_addr):
                        validate_passthrough_args(state, params.get_function(callee_addr), is_call)

            yield insn.ea, state

            # we need to go deeper
            if callee is not None:
                ret_value = None

                callee_model = params.get_function(callee.start_ea)

                callee_starting_state = state_t()
                populate_arguments(callee_starting_state, callee_model.cc, state, is_call)

                params.depth -= 1
                for (ea, callee_state) in function_execution_flow(
                    callee, callee_starting_state, params
                ):
                    # get callee return value
                    if (
                        callee_state.ret is not None
                        and callee.contains(callee_state.ret.where)
                        and not isinstance(ret_value, sid_t)
                    ):
                        ret_value = callee_state.ret.code

                    yield ea, callee_state
                params.depth += 1

                # keep track of used arguments
                validate_passthrough_args(state, callee_model, is_call)

                if is_call:
                    # keep return value from function
                    if ret_value is None:
                        ret_value = call_t(callee.start_ea, insn.ea)
                    set_ret_value(state, ret_value)

        prev_states[node] = state

    fct_model.guess_function_cc(starting_state.arguments)


# copy arguments from caller state to callee state, depending on callee cc
def populate_arguments(
    callee_state: state_t, callee_cc: arch.abi_t, caller_state: state_t = None, is_call: bool = True
):
    for i in range(callee_cc.get_arg_count()):
        arg = None
        if caller_state is not None:
            arg = get_argument(callee_cc, caller_state, i, False, not is_call)

        if arg is None or isinstance(arg, stack_ptr_t):  # stack tracking is local to function
            set_argument(callee_cc, callee_state, i, arg_t(i))
        else:
            # copy so we have a fresh reference for args count tracking
            set_argument(callee_cc, callee_state, i, copy.copy(arg))


# generate cpu state for input function
# params.depth = when propagating in function call/jumps, max depth to go
# -1 = follow until no more sid_t in state, 0 = don't follow calls
def generate_state(func: idaapi.func_t, params: propagation_param_t = None, cc: arch.abi_t = None):
    starting_state = state_t()

    if params is None:
        params = propagation_param_t()

    if cc is None:
        cc = get_abi()

    # Set up starting state with arguments
    populate_arguments(starting_state, cc)

    for (ea, state) in function_execution_flow(func, starting_state, params):
        yield ea, state
