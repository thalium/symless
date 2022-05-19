import bisect
import collections
import enum
from typing import List, Tuple

import idaapi
import idautils

import symless.allocators as allocators
import symless.cpustate.cpustate as cpustate
import symless.ida_utils as ida_utils
import symless.utils as utils
from symless.cpustate import mem_t


# from most interesting to last (for merge decisions)
class model_type(enum.IntEnum):
    STRUCTURE = 0
    VTABLE = 1
    STRUCTURE_UKWN_SIZE = 2
    UNVALID = 3


# Model of a structure
class model_t:
    def __init__(self, size: int, ea: int = None, type: model_type = model_type.STRUCTURE):
        self.sid = -1  # set by context_t
        self.size = size

        self.ea = []  # vtable ea or struc allocations ea
        if ea is not None:
            self.ea.append(ea)

        self.type = type
        self.members = list()  # sorted list of (offset, size)
        self.operands = dict()  # (insn.ea, op_index) -> (shift, offset)
        self.symname = None

        # class ctor ea
        self.ctor_ea = None  # first method the object went in
        self.last_load = None  # last vtable load ea

        if self.is_vtable():
            self.owners = set()  # set of (model_t, offset) for vtables

            ptr_size = ida_utils.get_ptr_size()
            self.members_names = [None for _ in range(int(size / ptr_size))]  # list of names

            self.total_xrefs = 0  # sum of all virtual functions (data) xrefs count
        else:
            self.vtables = dict()  # offset -> list of vtable_sid
            self.members_names = []

    def get_guessed_names(self):
        if self.is_vtable():
            return []
        else:
            return self.members_names

    # add struct member
    def add_member(self, offset: int, size: int) -> bool:
        if self.size > 0 and offset + size > self.size:
            size = self.size - offset

        if size <= 0:
            return False

        insert_struct_member(self.members, offset, size)

        return True

    # add vtable ptr at given offset
    def add_vtable(self, offset: int, vtable_sid: int):
        if self.size > 0 and (offset + ida_utils.get_ptr_size()) > self.size:
            return False

        if offset not in self.vtables:
            self.vtables[offset] = list()
        self.vtables[offset].append(vtable_sid)

        return True

    # add operand at (ea, n) associated to given member at offset, with given struct shift
    def add_operand(self, offset: int, ea: int, n: int, shift: int):
        # TODO handle the fact that same operand can be applied to multiple members of the same struct
        self.operands[(ea, n)] = (shift, offset)

    def guess_member_name(self, target: mem_t, offset: int):
        # state.get_
        name_target = idaapi.get_name(target.addr)
        if name_target is not None:
            utils.logger.debug(
                f"name = {name_target} addr = {hex(target.addr)} offset={hex(offset)}"
            )
            self.members_names += [(offset, name_target)]

    # sorted list of (offset, vtable_sid)
    def get_vtables(self):
        keys = list(self.vtables.keys())
        keys.sort()
        for offset in keys:
            yield (offset, self.vtables[offset][-1])

    # get current vtable (last encountered while propagating)
    def get_vtable(self, offset: int) -> int:
        try:
            return self.vtables[offset][-1]
        except KeyError:
            return -1

    def get_shift_for_operand(self, ea: int, n: int) -> int:
        return self.operands[(ea, n)][0]

    def get_operands(self):
        for key in self.operands.keys():
            (ea, n) = key
            yield (ea, n, self.operands[key][0])

    def is_empty(self):
        return len(self.members) == 0

    def is_vtable(self):
        return self.type == model_type.VTABLE

    def is_struct(self):
        return self.type == model_type.STRUCTURE

    def is_varsize_struct(self):
        return self.type == model_type.STRUCTURE_UKWN_SIZE

    # get member index for given offset
    def get_closest_member(self, offset: int) -> int:
        i = 0
        while i < len(self.members) and self.members[i][0] < offset:
            i += 1
        return i

    # update ctor_ea if last loaded vtable does no confirm it
    def confirm_ctor_ea(self):
        if self.last_load is not None:
            ctor_ea = idaapi.get_func(self.last_load).start_ea

            # first encountered ctor does not belong to class, discard it
            if ctor_ea != self.ctor_ea:
                self.ctor_ea = None

    # update size to match last member
    def update_size(self):
        utils.logger.debug("")
        if len(self.members) > 0:
            last = self.members[-1]
            self.size = last[0] + last[1]

    # can two structs contain the same inner struct
    def are_areas_similar(self, other, offset: int, offset_other: int, size: int) -> bool:
        i, j = self.get_closest_member(offset), other.get_closest_member(offset_other)
        end1, end2 = offset + size, offset_other + size

        while i < len(self.members) and j < len(other.members):
            m1 = self.members[i]
            m2 = other.members[j]

            if m1[0] >= end1 or m2[0] >= end2:
                break

            if m1[0] > m2[0]:
                if m2[0] + m2[1] > m1[0]:
                    return False
                j += 1
            elif m2[0] > m1[0]:
                if m1[0] + m1[1] > m2[0]:
                    return False
                i += 1
            else:
                if m1[1] != m2[1]:  # incompatible sizes
                    return False
                i += 1
                j += 1

        return True

    # are two models representing the same object
    def is_similar(self, other) -> bool:
        varsize_flag = (
            0 | (1 if self.is_varsize_struct() else 0) | (2 if other.is_varsize_struct() else 0)
        )

        # can't have 2 unknown size struct for same class
        if varsize_flag == 3:
            return False

        if (self.size != other.size and varsize_flag == 0) or self.is_vtable() != other.is_vtable():
            return False

        comp_size = min(self.size, other.size)

        # struct members are compatible
        if not self.are_areas_similar(other, 0, 0, comp_size):
            return False

        # similar vtables
        for (offset, vtables) in self.vtables.items():
            other_sid = other.get_vtable(offset)
            if other_sid > 0 and other_sid != vtables[-1]:
                return False

        return True

    # merge model other[from offset for size] into self[from 0 for size]
    def merge(self, other, offset: int, size: int, ctx, force_op: bool = False):
        i = other.get_closest_member(offset)

        # truncate preceding member if needed
        if i - 1 < len(other.members) and i > 0:
            previous = other.members[i - 1]
            if previous[0] + previous[1] > offset:
                other.members[i - 1] = (previous[0], offset - previous[0])

        # merge members
        while i < len(other.members):
            (off, siz) = other.members[i]

            effective_offset = off - offset
            if effective_offset >= size:
                break

            self.add_member(effective_offset, siz)

            del other.members[i]

        # merge vtables
        dq = collections.deque()
        for off in other.vtables:
            eoffset = off - offset
            if eoffset >= 0 and eoffset < size:
                dq.append(off)

                if eoffset not in self.vtables:
                    self.vtables[eoffset] = other.vtables[off]

        while len(dq) > 0:
            other.vtables.pop(dq.pop())

    # merge full model other into self (must be of same size) - erase other
    def merge_full(self, other, ctx):
        self.merge(other, 0, self.size, ctx, True)

        # merge operands
        self.operands.update(other.operands)

        # remove other from ctx.all_operands
        for key in other.operands:
            ctx.all_operands[key][1].remove(other.sid)
            ctx.all_operands[key][1].add(self.sid)

        if self.is_struct() and other.is_struct():
            self.ea += other.ea

        ctx.models[other.sid] = discarded_t(other.sid, self.sid)  # discard old model

    def get_name(self) -> str:
        if self.has_name():
            return self.symname
        if self.is_vtable():
            return f"ea_{self.get_ea():x}{idaapi.VTBL_SUFFIX}"
        return f"struct_{self.get_ea():x}"

    def set_name(self, name: str):
        self.symname = name

    def has_name(self):
        return self.symname is not None

    def get_ea(self) -> int:
        return self.ea[0]

    def __lt__(self, other):
        return self.sid < other.sid

    def __hash__(self):
        return self.sid

    def __eq__(self, other):
        return isinstance(other, model_t) and self.sid == other.sid

    def dump(self, shift=""):
        utils.logger.debug(
            "%s%s (size: %d) - %s:" % (shift, self.get_name(), self.size, str(self.type))
        )
        shift += "  "

        utils.logger.debug("%smembers (%d):" % (shift, len(self.members)))
        for offset, size in self.members:
            utils.logger.debug(
                "%s%x - %x%s"
                % (
                    shift,
                    offset,
                    size,
                    " -> vtable" if not self.is_vtable() and offset in self.vtables else "",
                )
            )
        utils.logger.debug("")


# Model of a function
class function_t:
    def __init__(self, ea: int):
        self.ea = ea
        self.args_count = 0
        self.args = [
            set() for i in range(cpustate.get_abi().get_arg_count())
        ]  # sets of (sid, shift)
        self.ret = set()  # set of (sid, shift)
        self.is_virtual = False  # part of a vtable
        self.cc = None  # guessed calling convention

    # update arguments candidates & calling convention
    def merge(self, original: cpustate.function_t):

        # merge arguments
        self.args_count = max(self.args_count, original.args_count)
        for i in range(self.args_count):
            self.args[i].update(original.args[i])

        # merge cc
        if self.cc is not None and self.cc != original.cc:
            utils.logger.error(
                'Guessing multiple cc for function 0x%x, "%s" != "%s"'
                % (self.ea, self.cc.name, original.cc.name)
            )
        else:
            self.cc = original.cc

    # add ret candidates
    def add_ret(self, sid: int, shift: int):
        self.ret.add((sid, shift))

    def discard_arg(self, index: int):
        self.args[index] = None

    def discard_all_args(self):
        self.args = [None for i in range(cpustate.get_abi().get_arg_count())]
        self.ret = None

    # purge from discarded models, or badly shifted ones
    def purge(self, ctx):
        args = self.args[: self.args_count] + [self.ret]

        for arg in args:
            # get invalid arguments
            dq = collections.deque()
            for sid, shift in arg:
                model = ctx.models[sid]
                if not isinstance(model, model_t) or shift < 0 or shift >= model.size:
                    dq.append((model, shift))

            # pop / replace invalids
            while len(dq) > 0:
                (model, shift) = dq.pop()
                arg.remove((model.sid, shift))

                if shift >= 0 and not isinstance(model, model_t):
                    replace = model.get_model(ctx)
                    if shift < replace.size:
                        arg.add((replace.sid, shift))

    def has_args(self) -> bool:
        return self.args[0 : self.args_count].count(None) != self.args_count or self.ret is not None

    def get_args(self):
        for i in range(self.args_count):
            current = self.args[i]
            if current is not None:
                yield (i, current[0], current[1])


# Record of models
class context_t:
    def __init__(self):
        self.models = []  # list of model_t, may contain Nones for discarded models
        self.allocators = set()  # set of allocators.allocator_t
        self.all_operands = dict()  # (insn.ea, op_index) -> (op_boundary, set of models_sids)
        self.vtables = dict()  # vtable_ea -> model_t
        self.functions = dict()  # ea -> function_t

    def add_model(self, model: model_t):
        model.sid = self.next_sid()
        self.models.append(model)

    def get_models(self) -> List[model_t]:
        i, length = 0, len(self.models)
        while i < length:
            if isinstance(self.models[i], model_t):
                yield self.models[i]
            i += 1

    # get ctors for already visited classes
    def get_visited_ctors(self) -> dict:
        utils.logger.debug("")
        out = dict()
        for model in self.get_models():
            if model.ctor_ea is not None:
                out[model.ctor_ea] = model
        return out

    def get_or_create_vtable(self, ea: int, size: int) -> model_t:
        if ea in self.vtables:
            return self.vtables[ea]

        ptr_size = ida_utils.get_ptr_size()
        vtable = model_t(size, ea, model_type.VTABLE)

        # name vtable from existing struct
        existing_struc = ida_utils.get_ea_vtable(ea)
        if existing_struc is not None:
            vtable.set_name(idaapi.get_struc_name(existing_struc.id))

        i = 0
        presents = set()
        for fea in ida_utils.vtable_members(ea):
            # mark func as virtual
            self.get_function(fea).is_virtual = True

            # set member names
            index = i * ptr_size
            vtable.add_member(index, ptr_size)
            if fea in presents:
                vtable.members_names[i] = f"method_{fea:08x}_{index:x}"
            else:
                presents.add(fea)
                vtable.members_names[i] = f"method_{fea:08x}"
            i += 1

            # update vtable total xrefs count
            vtable.total_xrefs += len(ida_utils.get_data_references(fea))

        self.add_model(vtable)
        self.vtables[ea] = vtable
        return vtable

    def add_allocator(self, allocator: allocators.allocator_t):
        self.allocators.add(allocator)

    def add_operand_for(self, ea: int, n: int, boundary: int, model: model_t):
        key = (ea, n)
        if key not in self.all_operands:
            self.all_operands[key] = (boundary, set())
        self.all_operands[key][1].add(model.sid)

    def get_function(self, ea: int):
        if ea not in self.functions:
            self.functions[ea] = function_t(ea)
        return self.functions[ea]

    def has_function(self, ea: int) -> bool:
        return ea in self.functions

    def update_functions(self, visited: dict):
        utils.logger.debug("")
        for ea, function in visited.items():
            if not function.has_args():
                continue

            self.get_function(ea).merge(function)

    def update_function_ret(self, ea: int, sid: int, shift: int):
        self.get_function(ea).add_ret(sid, shift)

    def next_sid(self) -> int:
        return len(self.models)

    def dump(self):
        utils.logger.debug("# Memory allocators:")
        for alloc in self.allocators:
            utils.logger.debug(alloc)

        utils.logger.debug("\n# Models:\n")
        for model in self.get_models():
            model.dump()
            utils.logger.debug("")


# link between discarded model and its replacement
class discarded_t:
    def __init__(self, sid: int, replace: int):
        self.sid = sid
        self.replace = replace

    def get_model(self, ctx: context_t) -> model_t:
        current = self
        while isinstance(current, discarded_t):
            current = ctx.models[current.replace]
        return current


# Add struct member to list, handle conflicts
def insert_struct_member(members: list, offset: int, size: int):
    end = offset + size
    index = bisect.bisect_left(members, (offset, size))

    if index > 0:
        previous = index - 1
        if members[previous][0] + members[previous][1] > offset:  # member overlap

            if members[previous][0] == offset:
                insert_struct_member(
                    members,
                    members[previous][0] + members[previous][1],
                    size - members[previous][1],
                )
                return
            else:
                members[previous] = (members[previous][0], offset - members[previous][0])

    if index < len(members) and end > members[index][0]:
        if members[index][0] == offset:
            if size == members[index][1]:  # identicals
                return
            members[index] = (end, members[index][1] - size)
        else:
            size = members[index][0] - offset

    members.insert(index, (offset, size))


""" Effective vtable selection """

# count of xrefs to vtable functions
def vtable_ref_count(vtable_ea) -> Tuple[int, int]:
    count, size = 0, 0
    for fea in ida_utils.vtable_members(vtable_ea):
        count += len(ida_utils.get_data_references(fea))
        size += 1
    return count, size


# which one is the most derived vtable
# base heuristics: biggest one, or the one with the less referenced functions
def most_derived_vtable(v1: int, v2: int) -> int:
    c1, s1 = vtable_ref_count(v1)
    c2, s2 = vtable_ref_count(v2)
    if s1 > s2:
        return v1
    if s2 > s1:
        return v2
    if c1 > c2:
        return v2
    return v1


# most derived vtable but more efficient, using cached values
def most_derived_vtable_from_cache(v1: model_t, v2: model_t) -> model_t:
    c1, s1 = v1.total_xrefs, len(v1.members_names)
    c2, s2 = v2.total_xrefs, len(v2.members_names)
    if s1 > s2:
        return v1
    if s2 > s1:
        return v2
    if c1 > c2:
        return v2
    return v1


# from list of all loaded vtables, in order, returns list of unique ones
def get_unique_vtables(vtables: list) -> list:
    i, length = 0, len(vtables)
    while i < length:
        if vtables.index(vtables[i]) != i:
            break
        i += 1
    return vtables[:i]


# from list of loaded vtables, in ctor/dtor order, return them sorted in ctor order (from base vtable to most derived vtable)
def get_effective_vtables(vtables: list, ctx: context_t) -> list:
    # uniques vtables, for order of load (ctor or dtor order)
    uniqs = get_unique_vtables(vtables)

    if len(uniqs) == 1:
        return uniqs

    # guess vtable order (ctor or dtor order)
    first, last = ctx.models[uniqs[0]], ctx.models[uniqs[-1]]
    effective = most_derived_vtable_from_cache(first, last)

    if first == effective:
        uniqs.reverse()

    return uniqs


# Solve conflicts on class vtable ptr
# select last original vtable loaded, aka last vtable used in ctor = effective one
def select_class_vtables(model: model_t, ctx: context_t):
    for offset in model.vtables:
        utils.logger.debug(model)
        if model.is_struct():  # propagation started with ctor
            model.vtables[offset] = get_unique_vtables(model.vtables[offset])
        else:  # model propagated in ctors/dtors, no specific order
            model.vtables[offset] = get_effective_vtables(model.vtables[offset], ctx)

        ctx.models[model.get_vtable(offset)].owners.add((model, offset))


""" Virtual methods propagation """

# propagate given state in all vtable functions
def analyze_vtable(
    vtable_ea: int, params: cpustate.propagation_param_t, start: cpustate.state_t, ctx: context_t
):
    for fea in ida_utils.vtable_members(vtable_ea):
        if params.should_propagate(start, fea, True, False):
            func = idaapi.get_func(fea)

            for ea, state in cpustate.function_execution_flow(func, start, params):
                handle_access(state, ctx)
                handle_read(state, ctx)
                handle_ret(state, ctx)


# continue model building by analyzing newly found virtual functions
def analyze_model_vtables(model: model_t, params: cpustate.propagation_param_t, ctx: context_t):
    utils.logger.debug("")
    # select effective vtables before propagation
    select_class_vtables(model, ctx)

    cc = cpustate.get_object_cc()

    for offset in model.vtables:
        utils.logger.debug(offset)

        starting_state = cpustate.state_t()
        cpustate.populate_arguments(starting_state, cc)
        cpustate.set_argument(cc, starting_state, 0, cpustate.sid_t(model.sid, offset))

        # analyze all candidates for given offset, not only the effective vtable
        for sid in model.vtables[offset]:
            vtable_ea = ctx.models[sid].get_ea()
            analyze_vtable(vtable_ea, params, starting_state, ctx)


""" Propagation actions handlers """

# handle function call, record possible ctor
def handle_call(state: cpustate.state_t, ctx: context_t):
    if state.call_type == cpustate.call_type_t.CALL and state.call_to != 0:
        cur = cpustate.get_argument(cpustate.get_object_cc(), state, 0, from_callee=False)
        if isinstance(cur, cpustate.sid_t) and cur.shift == 0:
            model = ctx.models[cur.sid]
            if model.ctor_ea is None:
                model.ctor_ea = state.call_to


# handle function ret, record ret type for function typing
def handle_ret(state: cpustate.state_t, ctx: context_t):
    if state.ret is not None and isinstance(state.ret.code, cpustate.sid_t):
        code = state.ret.code
        fea = idaapi.get_func(state.ret.where).start_ea
        ctx.update_function_ret(fea, code.sid, code.shift)


# Build model members from state access
def handle_access(state: cpustate.state_t, ctx: context_t):
    for access in state.access:
        disp = access.key

        # use previous registers values, before insn was computed
        cur = state.get_previous_register(disp.reg)

        if isinstance(cur, cpustate.sid_t):
            offset = cpustate.ctypes.c_int32(disp.offset + cur.shift).value
            if cur.shift < 0 or offset < 0:
                continue
            model: model_t
            model = ctx.models[cur.sid]
            if (model.size > 0 and cur.shift >= model.size) or not model.add_member(
                offset, disp.nbytes
            ):
                continue

            model.add_operand(offset, access.ea, access.n, cur.shift)

            boundary = cpustate.ctypes.c_int32(disp.offset).value  # lower boundary
            if boundary >= 0:
                boundary += disp.nbytes  # upper boundary
            ctx.add_operand_for(access.ea, access.n, boundary, model)


# Handle writes to struc members
def handle_write(ea: int, state: cpustate.state_t, ctx: context_t):
    ptr_size = ida_utils.get_ptr_size()
    for write in state.writes:
        utils.logger.debug(write)
        disp = write.disp
        target = write.src
        cur = state.get_previous_register(disp.reg)

        # mov [sid + offset], mem -> vtable loading
        if isinstance(cur, cpustate.sid_t) and isinstance(target, cpustate.mem_t):
            if disp.nbytes != ptr_size:  # not a pointer
                continue

            offset = cpustate.ctypes.c_int32(disp.offset + cur.shift).value
            if offset < 0:
                continue

            vtable_ea = target.get_val()
            vtbl_size = ida_utils.vtable_size(vtable_ea)
            model: model_t
            model = ctx.models[cur.sid]

            if vtbl_size == 0:  # Not a vtable
                model.guess_member_name(target, offset)
                continue

            if model.is_vtable():
                utils.logger.warning(
                    "propagation found %s having another vtable (0x%x) loaded at 0x%x. Ignoring.."
                    % (model.get_name(), vtable_ea, ea)
                )
                continue

            vtable = ctx.get_or_create_vtable(vtable_ea, vtbl_size)
            added = model.add_vtable(offset, vtable.sid)

            # set last loaded vtable, used in ctor identification
            if (
                added
                and offset == 0
                and model.vtables[0].index(vtable.sid) == len(model.vtables[0]) - 1
            ):
                model.last_load = ea


# Handle read of struct members
def handle_read(state: cpustate.state_t, ctx: context_t):
    ptr_size = ida_utils.get_ptr_size()

    for read in state.reads:
        disp = read.disp
        src = state.get_previous_register(disp.reg)

        # mov reg, [sid + offset]
        if isinstance(src, cpustate.sid_t):
            if disp.nbytes != ptr_size:
                continue

            model = ctx.models[src.sid]
            if model.is_vtable():
                continue

            offset = cpustate.ctypes.c_int32(disp.offset + src.shift).value

            vtable_sid = model.get_vtable(offset)  # current vtable
            if vtable_sid < 0:
                continue

            # vtable ptr was read, inject it in state
            state.set_register(read.dst, cpustate.sid_t(vtable_sid))


# handle new cpu state
def handle_state(ea: int, state: cpustate.state_t, ctx: context_t):
    utils.logger.debug(f"handle_state {hex(ea)} {state}")
    handle_access(state, ctx)
    handle_write(ea, state, ctx)
    handle_read(state, ctx)
    handle_call(state, ctx)
    handle_ret(state, ctx)


""" Memory allocations analysis (all types of structs) """

# Type of allocation, used in state propagation
class allocation_type(enum.Enum):
    BEFORE_ALLOCATION = 0
    SIZE_PASSTHROUGH = 1
    STATIC_SIZE = 2


# Analyze function which calls the given allocator
# return True if the function is an allocator wrapper, otherwise builds the model
def analyze_allocator(
    func: idaapi.func_t, allocator: allocators.allocator_t, call_ea: int, ctx: context_t
) -> Tuple[bool, tuple]:
    atype = allocation_type.BEFORE_ALLOCATION
    params = cpustate.propagation_param_t(depth=0)

    model = None
    wrapper_args = None

    for ea, state in cpustate.generate_state(func, params, cpustate.get_default_cc()):
        if atype == allocation_type.BEFORE_ALLOCATION and ea == call_ea:
            action, size = allocator.on_call(state)

            if action == allocators.alloc_action_t.JUMP_TO_ALLOCATOR:
                return (True, size)

            if action == allocators.alloc_action_t.WRAPPED_ALLOCATOR:
                atype = allocation_type.SIZE_PASSTHROUGH
                wrapper_args = size

            # a struc/buffer is allocated
            elif action == allocators.alloc_action_t.STATIC_ALLOCATION:
                model = model_t(size, ea)
                ctx.add_model(model)
                cpustate.set_ret_value(state, cpustate.sid_t(model.sid, 0))

                params.depth = cpustate.MAX_PROPAGATION_RECURSION  # Start propagation in callees
                atype = allocation_type.STATIC_SIZE

            else:  # not a zone of interest
                return (False, None)

        elif atype == allocation_type.SIZE_PASSTHROUGH and state.ret:

            # function returns what returned the sub allocator
            if allocator.on_wrapper_ret(state, call_ea):
                return (True, wrapper_args)

        elif atype == allocation_type.STATIC_SIZE:  # handle model building
            handle_state(ea, state, ctx)

    if model is not None:
        # analyze virtual functions
        analyze_model_vtables(model, params, ctx)

        # fix ctor_ea
        model.confirm_ctor_ea()

        # update functions model
        ctx.update_functions(params.visited)

    return (False, None)


# Analyze the children of a memory allocator
def analyze_allocator_heirs(allocator: allocators.allocator_t, ctx: context_t):
    if allocator in ctx.allocators:  # avoid inifine recursion if crossed xrefs
        return

    ctx.add_allocator(allocator)

    for current in ida_utils.get_all_references(allocator.ea):

        insn = idautils.DecodeInstruction(current)
        if insn is None:
            utils.logger.debug(f"ignore xref {hex(current)}")
            continue

        utils.logger.debug(f"analyse xref {hex(current)}")

        if insn.itype in [
            idaapi.NN_jmp,
            idaapi.NN_jmpfi,
            idaapi.NN_jmpni,
            idaapi.NN_call,
            idaapi.NN_callfi,
            idaapi.NN_callni,
        ]:
            func = idaapi.get_func(current)
            if func is not None:
                is_allocator, args = analyze_allocator(func, allocator, current, ctx)
                if is_allocator:
                    wrapper = allocator.get_child(func.start_ea, args)
                    analyze_allocator_heirs(wrapper, ctx)


# Start building the model & locate memory allocators
# from the given entry points (list of allocator functions)
def analyze_allocations(imports: List[allocators.allocator_t], ctx: context_t):
    for i in imports:
        utils.logger.debug(i)
        analyze_allocator_heirs(i, ctx)


""" Ctors & dtors analysis (cpp classes only) """

# is given function a ctor/dtor (does it load a vtable into a class given as first arg)
def is_ctor(func: idaapi.func_t, load_addr: int) -> Tuple[bool, int]:
    state = cpustate.state_t()
    params = cpustate.propagation_param_t(depth=0)
    cpustate.set_argument(cpustate.get_object_cc(), state, 0, cpustate.sid_t(0))
    for ea, state in cpustate.function_execution_flow(func, state, params):
        if len(state.writes) > 0:
            write = state.writes[0]

            if not isinstance(write.src, cpustate.mem_t):
                continue

            if write.src.addr != load_addr:
                continue

            dst = state.get_previous_register(write.disp.reg)
            if isinstance(dst, cpustate.sid_t):  # arg 0 = struct ptr -> ctor/dtor
                offset = cpustate.ctypes.c_int32(write.disp.offset + dst.shift).value
                if offset >= 0:
                    return (True, offset)

            # vtable moved somewhere else
            return (False, -1)

    return (False, -1)


# get ctors & dtors entry points, grouped by classes
def get_ctors() -> dict:
    # associate each ctor/dtor to one vtable (effective table of one class)
    ctor_vtbl = dict()  # ctor_ea -> vtbl_ea
    for vtbl_ref, vtbl_addr in ida_utils.get_all_vtables():
        utils.logger.debug(f"{vtbl_ref} {vtbl_addr}")
        for xref in ida_utils.get_data_references(vtbl_ref):
            if not ida_utils.is_vtable_load(xref):
                continue

            func = idaapi.get_func(xref)
            if func is None:
                continue

            ctor, shift = is_ctor(func, vtbl_ref)
            if ctor and shift == 0:  # only take first vtable in account
                if func.start_ea in ctor_vtbl:
                    ctor_vtbl[func.start_ea] = most_derived_vtable(
                        vtbl_addr, ctor_vtbl[func.start_ea]
                    )
                else:
                    ctor_vtbl[func.start_ea] = vtbl_addr

    # regroup ctors/dtors by families
    mifa = dict()  # vtbl_ea -> list of ctors
    for ctor, vtbl in ctor_vtbl.items():
        utils.logger.debug(f"{ctor} {vtbl}")
        if vtbl not in mifa:
            mifa[vtbl] = collections.deque()
        mifa[vtbl].append(ctor)
    utils.logger.debug("")
    return mifa


# analyze unvisited ctors / dtors and build model
def analyze_ctors(ctx: context_t):
    utils.logger.debug("")
    visited = ctx.get_visited_ctors()
    utils.logger.debug("")

    count = 0
    cc = cpustate.get_object_cc()
    utils.logger.debug("")
    for fam in get_ctors().values():
        utils.logger.debug(fam)

        # was the model already generated ?
        model = None
        from_existing = False
        for ctor in fam:
            utils.logger.debug(ctor)
            if ctor in visited:
                model = visited[ctor]
                from_existing = True
                break

        # new model
        if model is None:
            model = model_t(-1, None, model_type.STRUCTURE_UKWN_SIZE)
            model.ctor_ea = fam[0]
            ctx.add_model(model)

        sstate = cpustate.state_t()
        cpustate.populate_arguments(sstate, cc)
        cpustate.set_argument(cc, sstate, 0, cpustate.sid_t(model.sid))

        params = cpustate.propagation_param_t()

        # propagate model in ctors / dtors
        for ctor in fam:
            utils.logger.debug(ctor)
            if not from_existing:
                model.ea.append(ctor)
            elif ctx.has_function(ctor):  # propagation was already done there for this model
                continue

            for ea, state in cpustate.function_execution_flow(
                idaapi.get_func(ctor), sstate, params
            ):
                handle_state(ea, state, ctx)

        # propagate model in virtual methods
        if not from_existing:
            analyze_model_vtables(model, params, ctx)

            # set final guessed size
            model.update_size()

        # update functions model
        ctx.update_functions(params.visited)

        count += 1

    utils.logger.info("%d additionnal classes retrieved from their vtables" % count)


""" Model generation main """

# Model generation
def generate_model(config_path: str) -> context_t:
    imports = allocators.get_entry_points(config_path)
    if imports is None:
        return None

    ctx = context_t()

    # retrieved structures allocated
    if len(imports) == 0:
        utils.logger.warning(
            "None of the defined allocators are present. No structure will be found from allocations"
        )
    else:
        analyze_allocations(imports, ctx)

    # retrieved classes from constructors
    analyze_ctors(ctx)

    return ctx
