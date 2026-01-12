import enum
from collections import defaultdict, deque
from typing import Collection, Dict, Iterable, Set, Tuple, Union

import ida_hexrays
import idaapi

import symless.allocators as allocators
import symless.cpustate.cpustate as cpustate
import symless.utils.ida_utils as ida_utils
import symless.utils.vtables as vtables
from symless.model import *

""" Entry points from memory allocations """


# Type of a memory allocation
class allocation_type(enum.Enum):
    WRAPPED_ALLOCATION = 0  # allocator is just a wrap calling another allocator
    STATIC_SIZE = 1  # static size allocation
    UNKNOWN = 2  # any other case we do not handle


# Analyze a given call to a memory allocator
# defines if the caller is an allocator wrapper, or if the call is a static allocation (known size)
def analyze_allocation(
    caller: idaapi.func_t, allocator: allocators.allocator_t, call_ea: int
) -> Tuple[allocation_type, Union[allocators.allocator_t, alloc_entry_t, None]]:
    action, wrapper_args = None, None

    params = cpustate.dflow_ctrl_t(depth=0)
    for ea, sub_ea, state in cpustate.generate_state(caller, params):
        if ea == call_ea and state.has_call_info() and action is None:
            action, wrapper_args = allocator.on_call(state)

            # caller calls allocator, with size argument passed through
            if action == allocators.alloc_action_t.WRAPPED_ALLOCATOR:
                pass

            # known size allocation
            elif action == allocators.alloc_action_t.STATIC_ALLOCATION:
                return (allocation_type.STATIC_SIZE, alloc_entry_t(ea, sub_ea, wrapper_args, state.mba))

            # unknown size allocation
            elif action == allocators.alloc_action_t.UNDEFINED:
                return (allocation_type.UNKNOWN, None)

        # allocator wrapper returns the allocation
        elif action and state.has_ret_info() and allocator.on_wrapper_ret(state, call_ea):
            return (allocation_type.WRAPPED_ALLOCATION, allocator.get_child(caller.start_ea, wrapper_args))

    return (allocation_type.UNKNOWN, None)


# Analyze all calls to a memory allocator and its wrappers
# returns a set of entrypoints (static allocations) made with this allocator
def analyze_allocator_heirs(
    allocator: allocators.allocator_t,
    allocs: Set[allocators.allocator_t],
    entries: entry_record_t,
):
    if allocator in allocs:  # avoid infinite recursion if crossed xrefs
        return
    allocs.add(allocator)

    # for all xrefs to allocator
    for allocation_ea in ida_utils.get_all_references(allocator.ea):
        # function referencing the allocator
        caller = idaapi.get_func(allocation_ea)
        if caller is None:
            continue

        # instruction referencing the allocator
        call_insn = ida_utils.get_ins_microcode(allocation_ea)
        if call_insn is None:
            continue

        utils.g_logger.debug(f"Analyzing xref {allocation_ea:#x}: {call_insn.dstr()} to allocator {allocator}")

        # verify this is a call / jmp instruction
        if call_insn.opcode not in (ida_hexrays.m_call, ida_hexrays.m_icall, ida_hexrays.m_goto, ida_hexrays.m_ijmp):
            continue

        type, alloc = analyze_allocation(caller, allocator, allocation_ea)

        if type == allocation_type.WRAPPED_ALLOCATION:
            utils.g_logger.debug(f"{allocation_ea:#x} is a wrap around {allocator}")
            analyze_allocator_heirs(alloc, allocs, entries)

        elif type == allocation_type.STATIC_SIZE:
            utils.g_logger.debug(f"{allocation_ea:#x} is a static allocation of {alloc.size:#x}")
            entries.add_entry(alloc, True)


# get all entrypoints from defined allocators
def get_allocations_entrypoints(
    imports: Iterable[allocators.allocator_t], entries: entry_record_t
) -> Set[allocators.allocator_t]:
    allocators = set()

    for i in imports:
        analyze_allocator_heirs(i, allocators, entries)

    return allocators


""" Entry points from ctors & dtors """


# a constructor / destructor and the vtables it loads into the 'this' object
class ctor_t:
    def __init__(self, func: idaapi.func_t):
        self.func = func

        # vtables loaded into the 'this' object by this ctor
        self.vtables: Dict[vtables.vtable_t, Optional[int]] = dict()  # vtbl_ea -> load_offset

    # get what we think is the right vtable for the class associated with this ctor
    def get_associated_vtable(self) -> Tuple[vtables.vtable_t, int]:
        candidates = [(vtbl, off) for (vtbl, off) in self.vtables.items() if off is not None]
        candidates.sort(key=lambda k: k[1], reverse=True)

        vtbl, off = candidates.pop()  # at least one candidate should be present
        while len(candidates) > 0:
            vtbl2, off2 = candidates.pop()
            if off2 != off:
                break
            vtbl = vtbl.get_most_derived(vtbl2)  # conflict, try to find the inheriting vtable

        return (vtbl, off)


# analyse given ctor, returns True if it really is a ctor
def analyze_ctor(ctor: ctor_t) -> bool:
    ptr_size = ida_utils.get_ptr_size()
    yet_to_see = set(ctor.vtables.keys())

    mba = ida_utils.get_func_microcode(ctor.func)
    if mba is None:
        return False

    params = cpustate.dflow_ctrl_t(depth=0)
    state = cpustate.state_t(mba, params.get_function_for_mba(mba))

    if state.fct.get_args_count() == 0:  # function does not take a 'this' argument
        return False
    state.set_var_from_loc(state.fct.get_argloc(0), cpustate.sid_t(0))

    ret = False
    for _, _, state in cpustate.function_data_flow(state, params):
        if len(yet_to_see) == 0:  # nothing more to see
            return ret

        for write in state.writes:
            if write.size != ptr_size or not isinstance(write.value, cpustate.mem_t):
                continue

            val = write.value.get_uval()
            if val not in yet_to_see:  # written value is one of our vtables ea
                continue
            yet_to_see.remove(val)

            # value is written in our 'this' object
            if not isinstance(write.target, cpustate.sid_t):
                continue

            # update shift for vtable
            utils.g_logger.debug(f"Load for vtbl {val:#x} into this:{write.target.shift:x}")
            ctor.vtables[val] = write.target.shift
            ret = True

    return ret


# get ctors & dtors families
def get_ctors() -> Dict[int, Collection[ctor_t]]:
    all_ctors: Dict[int, ctor_t] = dict()
    ctors_for_family: Dict[int, Collection[ctor_t]] = defaultdict(deque)

    # make record of candidates ctors & the vtables they load
    for vtbl in vtables.get_all_vtables():
        for xref in vtbl.get_loads():
            fct = idaapi.get_func(xref)  # can not return None
            if fct.start_ea not in all_ctors:
                all_ctors[fct.start_ea] = ctor_t(fct)
            all_ctors[fct.start_ea].vtables[vtbl] = None

    # analyze all ctors, find the base vtable for their class
    for ctor in all_ctors.values():
        utils.g_logger.debug(
            f"Analyzing fct {ctor.func.start_ea:#x} for {len(ctor.vtables.keys())} vtables loads into 'this'"
        )
        if not analyze_ctor(ctor):
            continue

        vtbl, offset = ctor.get_associated_vtable()
        utils.g_logger.info(f"Found one ctor/dtor @ {ctor.func.start_ea:#x} for vtbl {vtbl.ea:#x} (off {offset:#x})")

        if offset != 0:  # we are only interested in vtables loaded at off:0
            continue

        ctors_for_family[vtbl.ea].append(ctor)

    return ctors_for_family


# get all entrypoints from identified ctors / dtors
def get_ctors_entrypoints(entries: entry_record_t):
    for fam in get_ctors().values():
        for i, ctor in enumerate(fam):
            entries.add_entry(arg_entry_t(ctor.func.start_ea, 0), True, i == 0)


# find root entrypoints, from classes & allocators found in the base
def retrieve_entrypoints(imports: Iterable[allocators.allocator_t]) -> context_t:
    entries = entry_record_t()

    allocators = get_allocations_entrypoints(imports, entries)

    get_ctors_entrypoints(entries)

    return context_t(entries, allocators)
