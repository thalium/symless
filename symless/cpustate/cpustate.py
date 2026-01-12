from collections import deque
from collections.abc import Callable
from typing import Collection, Dict, Generator, List, Set, Tuple

import ida_hexrays
import idaapi

import symless.config as config
import symless.utils.ida_utils as ida_utils
import symless.utils.utils as utils
from symless.cpustate import *

# max functions depth to propagate a structure
MAX_PROPAGATION_RECURSION = 100


# handles mov (mop_r | mop_S), (mop_r | mop_S)
def handle_mov_var_var(state: state_t, insn: ida_hexrays.minsn_t):
    v = state.get_var_from_mop(insn.l)
    state.set_var_from_mop(insn.d, v)


# handles mov mop_n, (mop_r | mop_S)
def handle_mov_imm_var(state: state_t, insn: ida_hexrays.minsn_t):
    v = int_t(insn.l.nnn.value, insn.d.size)
    state.set_var_from_mop(insn.d, v)


# handles mov mop_v, (mop_r | mop_S)
def handle_mov_gbl_var(state: state_t, insn: ida_hexrays.minsn_t):
    gvalue = ida_utils.get_nb_bytes(insn.l.g, insn.d.size)
    if gvalue is None:
        return state.drop_var_from_mop(insn.d)
    v = mem_t(gvalue, insn.l.g, insn.d.size)
    state.set_var_from_mop(insn.d, v)


# handles mov mop_a, (mop_r | mop_S)
def handle_mov_addr_var(state: state_t, insn: ida_hexrays.minsn_t):
    if insn.l.a.t != ida_hexrays.mop_v:  # mop_l, mop_S or mop_r
        return state.drop_var_from_mop(insn.d)
    v = mem_t(insn.l.a.g, insn.l.a.g, insn.d.size)
    state.set_var_from_mop(insn.d, v)


# handles stx (mop_r | mop_S), mop_r, (mop_r | mop_S)
# note: sel register is ignored
def handle_stx_var_var(state: state_t, insn: ida_hexrays.minsn_t):
    dst = state.get_var_from_mop(insn.d)
    # if not isinstance(dst, buff_t):  # stx to unknown
    #     return

    v = state.get_var_from_mop(insn.l)
    state.write_to(insn.ea, dst, insn.d, insn.l.size, v)


# handles stx mop_n, mop_r, (mop_r | mop_S)
# note: sel register is ignored
def handle_stx_imm_var(state: state_t, insn: ida_hexrays.minsn_t):
    dst = state.get_var_from_mop(insn.d)
    # if not isinstance(dst, buff_t):  # stx to unknown
    #     return

    v = int_t(insn.l.nnn.value, insn.l.size)
    state.write_to(insn.ea, dst, insn.d, insn.l.size, v)


# handles stx mop_v, mop_r, (mop_r | mop_S)
# note: sel register is ignored
def handle_stx_gbl_var(state: state_t, insn: ida_hexrays.minsn_t):
    dst = state.get_var_from_mop(insn.d)
    # if not isinstance(dst, buff_t):  # stx to unknown
    #     return

    gvalue = ida_utils.get_nb_bytes(insn.l.g, insn.l.size)
    if gvalue is not None:
        v = mem_t(gvalue, insn.l.g, insn.l.size)
        state.write_to(insn.ea, dst, insn.d, insn.l.size, v)


# handles stx mop_a, mop_r, (mop_r | mop_S)
# note: sel register is ignored
def handle_stx_addr_var(state: state_t, insn: ida_hexrays.minsn_t):
    dst = state.get_var_from_mop(insn.d)
    # if not isinstance(dst, buff_t):  # stx to unknown
    #     return

    if insn.l.a.t != ida_hexrays.mop_v:  # mop_l, mop_S or mop_r
        return
    v = mem_t(insn.l.a.g, insn.l.a.g, insn.l.size)
    state.write_to(insn.ea, dst, insn.d, insn.l.size, v)


# handles ldx mop_r, (mop_r | mop_S), (mop_r | mop_S)
# note: sel register is ignored
def handle_ldx_var_var(state: state_t, insn: ida_hexrays.minsn_t):
    src = state.get_var_from_mop(insn.r)
    state.read_from(insn.ea, src, insn.r, insn.d.size, insn.d)  # record read

    # set dst mop value
    deref = deref_t(src, insn.d.size)  # default : unknown access
    if isinstance(src, mem_t):
        v = ida_utils.get_nb_bytes(src.get_uval(), insn.d.size)  # try getting read value from memory
        deref = mem_t(v, src.get_uval(), insn.d.size) if v is not None else deref
    state.set_var_from_mop(insn.d, deref)


# handles xdu (mop_r | mop_S), (mop_r | mop_S)
def handle_xdu_var_var(state: state_t, insn: ida_hexrays.minsn_t):
    assert insn.l.size < insn.d.size

    src = state.get_var_from_mop(insn.l)
    if not isinstance(src, int_t):  # only makes sense to extend int
        return state.drop_var_from_mop(insn.d)

    v = copy.copy(src)
    v.size = insn.d.size
    state.set_var_from_mop(insn.d, v)


# handles xdu mop_n, (mop_r | mop_S)
def handle_xdu_imm_var(state: state_t, insn: ida_hexrays.minsn_t):
    handle_mov_imm_var(state, insn)


# handles xds (mop_r | mop_S), (mop_r | mop_S)
def handle_xds_var_var(state: state_t, insn: ida_hexrays.minsn_t):
    handle_xdu_var_var(state, insn)  # we do not differenciate signed / unsigned (should we ?)


# handles xds mop_n, (mop_r | mop_S)
def handle_xds_imm_var(state: state_t, insn: ida_hexrays.minsn_t):
    handle_xdu_imm_var(state, insn)


# handles call mop_v, (mop_f | mop_z)
def handle_call(state: state_t, insn: ida_hexrays.minsn_t):
    state.last_insn_type = last_insn_type_t.LAST_INSN_CALL

    # resolve call arguments
    if insn.d.t == ida_hexrays.mop_f:
        # assert(insn.l.g == insn.d.f.callee)  # insn.d.f.callee is not always resolved

        # we should not have non-flattened mop_d in the args list
        assert not any([i.t == ida_hexrays.mop_d for i in insn.d.f.args])

        state.call_args.extend([state.get_var_from_mop(i) for i in insn.d.f.args])
        utils.g_logger.debug(f"call site {insn.ea:#x} : {len(state.call_args)} argument(s)")

    # try to resolve callee
    callee = idaapi.get_func(insn.l.g)
    if callee is None or callee.start_ea != insn.l.g:
        return

    utils.g_logger.debug(f"call @ {insn.ea:#x} resolved to function {callee.start_ea:#x}")
    state.call_to = callee


# handles icall mop_r, mop_r, (mop_f | mop_z)
# note: sel register is ignored
def handle_icall(state: state_t, insn: ida_hexrays.minsn_t):
    state.last_insn_type = last_insn_type_t.LAST_INSN_CALL

    # resolve call arguments
    if insn.d.t == ida_hexrays.mop_f:
        assert not any([i.t == ida_hexrays.mop_d for i in insn.d.f.args])

        state.call_args.extend([state.get_var_from_mop(i) for i in insn.d.f.args])
        utils.g_logger.debug(f"icall site {insn.ea:#x} : {len(state.call_args)} argument(s)")

    # try to resolve callee
    off = state.get_var_from_mop(insn.r)
    if not isinstance(off, mem_t):
        return

    callee = idaapi.get_func(off.get_uval())
    if callee is None or callee.start_ea != off.get_uval():
        return

    utils.g_logger.debug(f"icall @ {insn.ea:#x} resolved to function {callee.start_ea:#x}")
    state.call_to = callee


# special case for ret handling
# there are no micro-insn for a ret
def handle_ret(state: state_t) -> state_t:
    state.reset()

    state.last_insn_type = last_insn_type_t.LAST_INSN_RET

    retloc = state.fct.get_retloc()
    if retloc is None:
        return state

    state.ret = state.get_var_from_loc(retloc)

    return state


# handles add (mop_r | mop_S), mop_n, (mop_r | mop_S)
def handle_add_var_imm(state: state_t, insn: ida_hexrays.minsn_t, sign: int = 1):
    v = state.get_var_from_mop(insn.l)
    if not isinstance(v, buff_t):
        return state.drop_var_from_mop(insn.d)

    shifted_v = v.shift_by(sign * insn.r.nnn.value, insn.r.size)
    state.set_var_from_mop(insn.d, shifted_v)

    # this add can be a lea we need to type
    # register an access for a field of size 0 (size is unknown)
    state.access_to(insn.ea, shifted_v, insn.l, 0)


# handles add (mop_r | mop_S), (mop_r | mop_S), (mop_r | mop_S)
def handle_add_var_var(state: state_t, insn: ida_hexrays.minsn_t, sign: int = 1):
    v = state.get_var_from_mop(insn.l)
    v2 = state.get_var_from_mop(insn.r)
    if not isinstance(v, buff_t) or not isinstance(v2, int_t):
        return state.drop_var_from_mop(insn.d)

    shifted_v = v.shift_by(sign * v2.get_val(), insn.r.size)
    state.set_var_from_mop(insn.d, shifted_v)

    state.access_to(insn.ea, shifted_v, insn.l, 0)  # dummy access


# handles sub (mop_r | mop_S), mop_n, (mop_r | mop_S)
def handle_sub_var_imm(state: state_t, insn: ida_hexrays.minsn_t):
    handle_add_var_imm(state, insn, -1)


# handles sub (mop_r | mop_S), (mop_r | mop_S), (mop_r | mop_S)
def handle_sub_var_var(state: state_t, insn: ida_hexrays.minsn_t):
    handle_add_var_var(state, insn, -1)


# handlers per instructions types
g_per_minsn_handlers = {
    ida_hexrays.m_mov: (
        # mov rax, rcx
        (
            (ida_hexrays.mop_r, ida_hexrays.mop_S),
            (ida_hexrays.mop_z,),
            (ida_hexrays.mop_r, ida_hexrays.mop_S),
            handle_mov_var_var,
        ),
        # mov #0, rax
        ((ida_hexrays.mop_n,), (ida_hexrays.mop_z,), (ida_hexrays.mop_r, ida_hexrays.mop_S), handle_mov_imm_var),
        # mov dword_0, rax
        ((ida_hexrays.mop_v,), (ida_hexrays.mop_z,), (ida_hexrays.mop_r, ida_hexrays.mop_S), handle_mov_gbl_var),
        # mov &dword_0, rax
        ((ida_hexrays.mop_a,), (ida_hexrays.mop_z,), (ida_hexrays.mop_r, ida_hexrays.mop_S), handle_mov_addr_var),
    ),
    ida_hexrays.m_stx: (
        # stx rax, ds, rcx
        (
            (ida_hexrays.mop_r, ida_hexrays.mop_S),
            (ida_hexrays.mop_r,),
            (ida_hexrays.mop_r, ida_hexrays.mop_S),
            handle_stx_var_var,
        ),
        # stx #0, ds, rcx
        ((ida_hexrays.mop_n,), (ida_hexrays.mop_r,), (ida_hexrays.mop_r, ida_hexrays.mop_S), handle_stx_imm_var),
        # stx dword_0, ds, rcx
        ((ida_hexrays.mop_v,), (ida_hexrays.mop_r,), (ida_hexrays.mop_r, ida_hexrays.mop_S), handle_stx_gbl_var),
        # stx &dword_0, ds, rcx
        ((ida_hexrays.mop_a,), (ida_hexrays.mop_r,), (ida_hexrays.mop_r, ida_hexrays.mop_S), handle_stx_addr_var),
    ),
    ida_hexrays.m_ldx: (
        # ldx ds, rax, rcx
        (
            (ida_hexrays.mop_r,),
            (ida_hexrays.mop_r, ida_hexrays.mop_S),
            (ida_hexrays.mop_r, ida_hexrays.mop_S),
            handle_ldx_var_var,
        ),
    ),
    ida_hexrays.m_xdu: (
        # xdu esi, rsi
        (
            (ida_hexrays.mop_r, ida_hexrays.mop_S),
            (ida_hexrays.mop_z,),
            (ida_hexrays.mop_r, ida_hexrays.mop_S),
            handle_xdu_var_var,
        ),
        # xdu #0, rsi
        ((ida_hexrays.mop_n,), (ida_hexrays.mop_z,), (ida_hexrays.mop_r, ida_hexrays.mop_S), handle_xdu_imm_var),
    ),
    ida_hexrays.m_xds: (
        # xds esi, rsi
        (
            (ida_hexrays.mop_r, ida_hexrays.mop_S),
            (ida_hexrays.mop_z,),
            (ida_hexrays.mop_r, ida_hexrays.mop_S),
            handle_xds_var_var,
        ),
        # xds #0, rsi
        ((ida_hexrays.mop_n,), (ida_hexrays.mop_z,), (ida_hexrays.mop_r, ida_hexrays.mop_S), handle_xds_imm_var),
    ),
    ida_hexrays.m_call: (
        # call sub_0, (arg1, arg2, ..)
        ((ida_hexrays.mop_v,), (ida_hexrays.mop_z,), (ida_hexrays.mop_f, ida_hexrays.mop_z), handle_call),
    ),
    ida_hexrays.m_icall: (
        # icall cs, x16, (arg1, arg2, ..)
        ((ida_hexrays.mop_r,), (ida_hexrays.mop_r,), (ida_hexrays.mop_f, ida_hexrays.mop_z), handle_icall),
    ),
    ida_hexrays.m_add: (
        # add rax, #0, rax
        (
            (ida_hexrays.mop_r, ida_hexrays.mop_S),
            (ida_hexrays.mop_n,),
            (ida_hexrays.mop_r, ida_hexrays.mop_S),
            handle_add_var_imm,
        ),
        # add rax, rcx, rax
        (
            (ida_hexrays.mop_r, ida_hexrays.mop_S),
            (ida_hexrays.mop_r, ida_hexrays.mop_S),
            (ida_hexrays.mop_r, ida_hexrays.mop_S),
            handle_add_var_var,
        ),
    ),
    ida_hexrays.m_sub: (
        # sub rax, #0, rax
        (
            (ida_hexrays.mop_r, ida_hexrays.mop_S),
            (ida_hexrays.mop_n,),
            (ida_hexrays.mop_r, ida_hexrays.mop_S),
            handle_sub_var_imm,
        ),
        # sub rax, rcx, rax
        (
            (ida_hexrays.mop_r, ida_hexrays.mop_S),
            (ida_hexrays.mop_r, ida_hexrays.mop_S),
            (ida_hexrays.mop_r, ida_hexrays.mop_S),
            handle_sub_var_var,
        ),
    ),
}


def get_handler_for_insn(insn: ida_hexrays.minsn_t) -> Optional[Callable[[state_t, ida_hexrays.minsn_t], None]]:
    family = g_per_minsn_handlers.get(insn.opcode, tuple())

    for lft, rgt, dst, handler in family:
        if insn.l.t in lft and insn.r.t in rgt and insn.d.t in dst:
            return handler

    return None


# debug: pretty print current state and insn
def dbg_dump_state_insn(insn: ida_hexrays.minsn_t, state: state_t):
    if utils.g_logger.level > config.LOG_LEVEL_VERBOSE_DEBUG:
        return

    utils.g_logger.log(config.LOG_LEVEL_VERBOSE_DEBUG, f"<----- insn & state @ {insn.ea:#x} ----->")
    utils.g_logger.log(config.LOG_LEVEL_VERBOSE_DEBUG, f"insn: {ida_utils.insn_str_full(insn)}")
    utils.g_logger.log(config.LOG_LEVEL_VERBOSE_DEBUG, f"state: {state}")


# divide a microinstruction into the subinstructions composing it
# returned instructions are ordered from first to last executed
# + patch instructions to use special kreg to transfer results
# note: this does not handle mop_d in mop_f arguments list
def flatten_minsn(minsn: ida_hexrays.minsn_t, mba: ida_hexrays.mba_t) -> Collection[ida_hexrays.minsn_t]:
    subs = deque()
    used_kregs = deque()

    # always copy, minsn in IDA Python 8.4 have a tendency to get freed prematurely. TODO: why ?
    # mk_copy &= any([(op.t == ida_hexrays.mop_d) for op in (minsn.l, minsn.r, minsn.d)])
    to_patch = ida_hexrays.minsn_t(minsn)

    # search operands for sub instructions
    for num_op in ("l", "r", "d"):
        op = getattr(to_patch, num_op)
        if op.t != ida_hexrays.mop_d:  # is op a subinsn
            continue

        # sub ret value is used as insn operand
        if op.d.d.t == ida_hexrays.mop_z:
            sub = ida_hexrays.minsn_t(op.d)  # copy to patch

            # kreg to use for transfering sub ret to insn
            kreg = mba.tmp_result_kregs.pop()
            used_kregs.append(kreg)
            krop = ida_hexrays.mop_t(kreg, op.size)  # make mop_r

            # sub ret to kreg
            sub.d = krop

            # sub may also contain sub instructions
            subs.extend(flatten_minsn(sub, mba))

        # sub-insn does not return a value (m_call)
        else:
            # insn should read call ret from call_result_kreg
            # call_result_kreg is set by flow_in_callee
            krop = ida_hexrays.mop_t(mba.call_result_kreg, op.size)

            subs.extend(flatten_minsn(op.d, mba))

        # replace minsn original operand with kreg
        setattr(to_patch, num_op, krop)

    # release used kregs
    mba.tmp_result_kregs.extend(used_kregs)

    subs.append(to_patch)
    return subs


# process one instruction & update current state
def process_instruction(state: state_t, insn: ida_hexrays.minsn_t):
    # reset previous instruction state
    state.reset()

    # modify the current state according to the insn
    handler = get_handler_for_insn(insn)
    if handler is None:
        utils.g_logger.log(config.LOG_LEVEL_VERBOSE_DEBUG, f"unsupported insn @ {insn.ea:#x}")
        state.drop_var_from_mop(insn.d)
    else:
        handler(state, insn)

    # dump the new state
    dbg_dump_state_insn(insn, state)


# select most interesting state (most sid_t, call_t)
def select_state(states: List[state_t]) -> state_t:
    states.sort(key=lambda e: (e.get_nb_types(sid_t), e.get_nb_types(call_t)), reverse=True)
    return states[0]


# get the starting state for a basic block
# if many states are possible, select the one with the most info in it
def get_previous_state(block: ida_hexrays.mblock_t, prev_states: Dict[int, state_t]) -> state_t:
    npred = block.npred()
    initial = prev_states[idaapi.BADADDR]

    # get all candidates for previous state
    states = []
    for i in range(npred):
        prev = block.pred(i)
        if prev in prev_states:
            states.append(prev_states[prev])

    if len(states) == 0:
        return state_t(initial.mba, initial.fct)

    return select_state(states).copy()


# next node to visit from given list
def pop_node(nodes: Collection[Tuple[int, Set[int]]], visited: Set[int]) -> int:
    # default: next node in graph flow
    idx = 0

    # find a block with all its predecessor visited
    sel = [i for i, (_, preds) in enumerate(nodes) if len(preds.difference(visited)) == 0]

    if len(sel):
        idx = sel[0]

    # find first node in nodes with a visited pred
    else:
        sel = [i for i, (_, preds) in enumerate(nodes) if len(visited.intersection(preds)) > 0]

        if len(sel):
            idx = sel[0]

    node = nodes[idx][0]
    visited.add(node)  # update visited
    del nodes[idx]  # remove node from list

    return node


def walk_topological(mba: ida_hexrays.mba_t) -> Generator[int, None, None]:
    # generate a list of nodes with predecessors
    nodes: Collection[Tuple[int, Set[int]]] = list()

    cur: ida_hexrays.mblock_t = mba.blocks
    while cur:
        # avoid empty blocks (head, tail & other purged blocks)
        if not cur.empty():
            preds = set(cur.pred(i) for i in range(cur.npred()) if not mba.get_mblock(cur.pred(i)).empty())
            nodes.append((cur.serial, preds))
        cur = cur.nextb

    visited: Set[int] = set()
    while len(nodes):
        yield pop_node(nodes, visited)


# Injector into state_t
class injector_t:
    def __init__(self, callback=None, when: int = 0):
        self.callback = callback  # callback(state: state_t, ea: int, sub_ea: int, before_update: bool)
        self.when = when  # when & 1 -> inject before, when & 2 -> inject after

    # inject value before processing current instruction
    def inject_before(self, state: state_t, ea: int, sub_ea: int):
        if self.when & 1:
            self.callback(state, ea, sub_ea, True)

    # inject value after the current instruction has been processed
    def inject_after(self, state: state_t, ea: int, sub_ea: int):
        if self.when & 2:
            self.callback(state, ea, sub_ea, False)


# should_propagate default callback
def always_propagate(fct: function_t, state: state_t) -> bool:
    return True


# data flow control parameters
# used to control propagation & retrieve information
class dflow_ctrl_t:
    def __init__(
        self,
        injector: injector_t = injector_t(),
        dive_cb=always_propagate,
        depth: int = MAX_PROPAGATION_RECURSION,
    ):
        self.injector = injector  # state injector
        self.visited: Dict[int, function_t] = dict()  # visited functions

        self.depth = depth  # current (reverse) depth
        self.max_depth = depth  # maximum depth to reach

        self.dive_cb = dive_cb  # callback deciding whether or not to dive into callee

    # is there a potential new state we need to visit
    def should_propagate(self, fct: function_t, state: state_t) -> bool:
        if self.depth < 0:  # max depth has been reached
            return False

        return self.dive_cb(fct, state)

    # has propagation passed by function
    def has_function(self, ea: int) -> bool:
        return ea in self.visited

    # get or create function
    def get_function_for_mba(self, mba: ida_hexrays.mba_t) -> function_t:
        if not self.has_function(mba.entry_ea):
            self.visited[mba.entry_ea] = function_t(mba)
        return self.visited[mba.entry_ea]

    # get or create function model for ea
    def get_function(self, fct: idaapi.func_t) -> Optional[function_t]:
        mba = ida_utils.get_func_microcode(fct)
        if mba is None:
            return None

        return self.get_function_for_mba(mba)


# copy callee's arguments from caller's state and propagate in callee
def flow_in_callee(
    call_ea: int, state: state_t, params: dflow_ctrl_t
) -> Generator[Tuple[int, int, state_t], None, None]:
    ret_value = call_t(idaapi.BADADDR if state.call_to is None else state.call_to.start_ea, call_ea)

    if state.call_to is not None:  # callee was resolved
        # microcode for callee
        mba = ida_utils.get_func_microcode(state.call_to)
        if mba is None:
            utils.g_logger.warning(f"No mba for callee {state.call_to.start_ea:#x}")
        else:
            # callee initial state
            cistate = state_t(mba, params.get_function_for_mba(mba))
            populate_arguments(cistate, state)

            params.depth -= 1

            # propagate in callee
            # peep at intermediate states to catch return values
            for ea, sea, cstate in function_data_flow(cistate, params):
                if isinstance(cstate.ret, absop_t) and cstate.ret.should_dive() and cstate.fct == cistate.fct:
                    ret_value = cstate.ret

                yield ea, sea, cstate

            params.depth += 1

    # set last call return value
    utils.g_logger.debug(f"ret value for call @ {call_ea:#x} set to {ret_value}")
    state.set_register(state.mba.call_result_kreg, ret_value)


# propagate in a function, using given initial state and parameters
def function_data_flow(initial_state: state_t, params: dflow_ctrl_t) -> Generator[Tuple[int, int, state_t], None, None]:
    mba = initial_state.mba

    # apply entry injection before deciding if we should continue
    # note: function's ea may differ from first insn.ea
    params.injector.inject_before(initial_state, mba.entry_ea, -1)

    # check if we can get new info by propagating there
    if not params.should_propagate(initial_state.fct, initial_state):
        return

    # record initial states for every node
    prev_states = dict()  # bb index -> state
    prev_states[idaapi.BADADDR] = initial_state

    # analyze calls & resolve callees arguments
    # this takes decompilation, do it after we are sure to analyze the function
    ida_utils.mba_analyze_calls(mba)

    # get nodes flooding order
    nodes = walk_topological(mba)

    # get entry basic block
    try:
        block = mba.get_mblock(next(nodes))
    except StopIteration:  # function has no block
        utils.g_logger.error(f"No entry block for function 0x{mba.entry_ea}")
        return

    insn = block.head  # first instruction
    state = initial_state  # first state

    # two minsn may have the same ea, use sub_ea to distinguish them
    sub_ea = 0

    # for every basic block
    while True:
        # for every instruction
        while insn:
            # for every subinstruction forming the instruction
            for subinsn in flatten_minsn(insn, mba):
                params.injector.inject_before(state, subinsn.ea, sub_ea)

                process_instruction(state, subinsn)

                # yield state after processing the insn
                yield subinsn.ea, sub_ea, state

                # we need to go deeper
                if state.has_call_info():
                    yield from flow_in_callee(subinsn.ea, state, params)

                params.injector.inject_after(state, subinsn.ea, sub_ea)
                sub_ea += 1

            # forget intermediate results
            state.drop_kregs()

            sub_ea = sub_ea if (insn.next and insn.ea == insn.next.ea) else 0
            insn = insn.next

        # tail basic block (ending with a ret)
        # there are no specific minsn for ret, a tail bb is only followed by the special BLT_STOP bb
        # note: a call to a noreturn function creates a special bb without any successor
        if block.nsucc() == 1 and mba.get_mblock(block.succ(0)).type == idaapi.BLT_STOP:
            yield block.end, -1, handle_ret(state)

        # add updated state to previous states
        prev_states[block.serial] = state

        # next block to process
        try:
            block = mba.get_mblock(next(nodes))
        except StopIteration:
            break

        insn = block.head
        state = get_previous_state(block, prev_states)


# copy arguments from caller state to callee state
def populate_arguments(callee_state: state_t, caller_state: Optional[state_t] = None):
    # make sure the number of arguments of the call site VS function's prototype are the same
    if caller_state and callee_state.fct.get_args_count() != len(caller_state.call_args):
        utils.g_logger.warning(
            f"fct {callee_state.get_fea():#x} mismatch between fct nargs ({callee_state.fct.get_args_count()}) and call site args {len(caller_state.call_args)}"
        )

    for i in range(callee_state.fct.get_args_count()):
        val = (
            caller_state.call_args[i] if (caller_state and i < len(caller_state.call_args)) else None
        )  # get caller value for the arg
        val = val if isinstance(val, absop_t) and val.should_dive() else arg_t(i)  # use default arg when required

        callee_state.set_var_from_loc(callee_state.fct.get_argloc(i), val)


# generate cpu state for given function
def generate_state(
    func: idaapi.func_t, params: Optional[dflow_ctrl_t] = None
) -> Generator[Tuple[int, int, state_t], None, None]:
    mba = ida_utils.get_func_microcode(func)
    if mba is None:
        utils.g_logger.error(f"no microcode for {func.start_ea}, no states generated")
        return

    params = params or dflow_ctrl_t()
    starting_state = state_t(mba, params.get_function_for_mba(mba))
    populate_arguments(starting_state)

    yield from function_data_flow(starting_state, params)
