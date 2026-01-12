from collections import deque
from typing import Collection, Generator, Optional, Tuple

import idaapi

import symless.cpustate.cpustate as cpustate
import symless.utils.ida_utils as ida_utils
import symless.utils.utils as utils

""" Utilities for identifying virtual tables """


# model for a virtual table
class vtable_t:
    def __init__(self, ea: int):
        self.ea = ea
        self.total_xrefs = 0  # total of xrefs on virtual methods

        # all virtual methods (fea, is_imported)
        self.members: Collection[Tuple[int, bool]] = deque()

        for fea, is_import in vtable_members(ea):
            self.members.append((fea, is_import))
            self.total_xrefs += len(ida_utils.get_data_references(fea))

        # list of ea where the vtable is loaded
        self.load_xrefs: Collection[int] = deque()

    def size(self) -> int:
        return len(self.members) * ida_utils.get_ptr_size()

    def add_load(self, xref: int):
        self.load_xrefs.append(xref)

    def get_loads(self) -> Collection[int]:
        return self.load_xrefs

    # search for places where this vtable is loaded into a structure
    def search_loads(self):
        for x in search_xrefs_for_vtable_load(self.ea, self.ea):
            self.add_load(x)

        # special RTTI case, vtable symbol may not point directly to the array of fct ptrs
        # ctor loads the vtable in the object like this:
        #   lea   rax, `vtable for'FooBar
        #   add   rax, 10h
        #   mov   [rbx], rax
        if len(self.get_loads()) == 0:
            for x in search_xrefs_for_vtable_load(self.ea - 2 * ida_utils.get_ptr_size(), self.ea):
                self.add_load(x)

    def get_members(self) -> Collection[Tuple[int, bool]]:
        return self.members

    def members_count(self) -> int:
        return len(self.members)

    # only contain imported functions
    def all_imports(self) -> bool:
        return all([is_import for _, is_import in self.members])

    # we think this really is a vtable
    def valid(self) -> bool:
        return self.members_count() > 0 and not self.all_imports()

    # get most derived vtable between self and other
    # decision based on some not-so-accurate heuristics
    def get_most_derived(self, other: "vtable_t") -> "vtable_t":
        # biggest vtable is the most derived
        if other.members_count() > self.members_count():
            return other
        if other.members_count() < self.members_count():
            return self

        # vtable with the most referenced methods is the base one
        # why ? its methods may be referenced from all inheriting vtables
        if self.total_xrefs > other.total_xrefs:
            return other
        if other.total_xrefs > self.total_xrefs:
            return self

        # most referenced vtable is the base one
        # as it is more loaded (also loaded in child classes ctors/dtors)
        if len(self.load_xrefs) > len(other.load_xrefs):
            return other

        return self

    def __hash__(self):
        return self.ea

    def __eq__(self, value):
        return (isinstance(value, int) and self.ea == value) or (isinstance(value, vtable_t) and self.ea == value.ea)


# returns the next member for the given vftable, None if we reached the end
def next_vtable_member(vtbl_ea: int, member_ea: int, ptr_size: int) -> Optional[Tuple[int, bool]]:
    fea = ida_utils.__dereference_pointer(member_ea, ptr_size) & ~1  # in case of thumb mode
    func = idaapi.get_func(fea)

    # addr is a function entry point
    if func and func.start_ea == fea:
        imported = False

    # addr points to an import
    elif idaapi.is_mapped(fea) and idaapi.getseg(fea).type == idaapi.SEG_XTRN:
        imported = True

    else:
        return None

    # if a reference is found on the member, consider it is not part of the current vtable
    if vtbl_ea != member_ea and (
        idaapi.get_first_dref_to(member_ea) != idaapi.BADADDR or idaapi.get_first_cref_to(member_ea) != idaapi.BADADDR
    ):
        return None

    return fea, imported


# yield all members of given vtable
def vtable_members(vtbl_ea: int) -> Generator[Tuple[int, bool], None, None]:
    ptr_size = ida_utils.get_ptr_size()

    current = vtbl_ea
    r = next_vtable_member(vtbl_ea, current, ptr_size)
    while r is not None:
        yield r
        current += ptr_size
        r = next_vtable_member(vtbl_ea, current, ptr_size)


# does the given xref points to a loading of vtbl_ea into a struct
def is_vtable_loaded_at(fct: idaapi.func_t, xref_ea: int, vtbl_ea: int) -> bool:
    block = ida_utils.get_block_microcode(fct, xref_ea)
    if not block:
        return False
    mbb, mba = block

    # flow in xref basic block, see if vtable is loaded & stored to a struct
    minsn = mbb.head
    state = cpustate.state_t(mba, None)

    utils.g_logger.debug(f"Looking for a load of vtable {vtbl_ea:#x} at {xref_ea:#x}")

    while minsn:  # for every bb's instructions
        for subinsn in cpustate.flatten_minsn(minsn, mba):  # for every sub instruction
            cpustate.process_instruction(state, subinsn)

            # check for vtable ea to be stored
            for write in state.writes:
                if (
                    write.size == ida_utils.get_ptr_size()
                    and isinstance(write.value, cpustate.mem_t)
                    and write.value.get_uval() == vtbl_ea
                ):
                    return True

        minsn = minsn.next

    return False


# search the xrefs of given ea for loads of vtbl_ea
def search_xrefs_for_vtable_load(ea: int, vtbl_ea: int) -> Generator[int, None, None]:
    for xref in ida_utils.get_data_references(ea):
        fct = idaapi.get_func(xref)

        # referenced from other data
        if fct is None and ida_utils.dereference_pointer(xref) == ea:
            yield from search_xrefs_for_vtable_load(xref, vtbl_ea)

        elif fct and is_vtable_loaded_at(fct, xref, vtbl_ea):
            yield xref


# get a model for the vtable at given address
# None if no vtable found at that address
def next_vtable(ea: int, end_ea: int) -> Tuple[Optional[vtable_t], int]:
    if not idaapi.is_loaded(ea):
        return None, idaapi.next_head(ea, end_ea)

    vtbl = vtable_t(ea)
    if vtbl.members_count() == 0:  # not an array of fct ptrs
        return None, idaapi.next_head(ea, end_ea)

    if vtbl.all_imports():  # we are not sure any of these are fct ptrs
        return None, ea + vtbl.size()

    # find vtable loading sites
    vtbl.search_loads()

    # vtable only if it is loaded by code
    if len(vtbl.get_loads()) != 0:
        return vtbl, ea + vtbl.size()

    return None, ea + vtbl.size()


# scans given segment for vtables
def get_all_vtables_in(seg: idaapi.segment_t) -> Generator[vtable_t, None, None]:
    utils.g_logger.info(
        "scanning segment %s[%x, %x] for vtables" % (idaapi.get_segm_name(seg), seg.start_ea, seg.end_ea)
    )

    current = seg.start_ea
    while current != idaapi.BADADDR and current < seg.end_ea:
        # do not cross functions
        chunk = idaapi.get_fchunk(current)
        if chunk is not None:
            current = chunk.end_ea
            continue

        # is a vtable ?
        vtbl, current = next_vtable(current, seg.end_ea)
        if vtbl:
            yield vtbl


# scans code segments for vtables
def get_all_vtables() -> Generator[vtable_t, None, None]:
    seg = idaapi.get_first_seg()
    while seg is not None:
        # search for vtables in .data and .text segments
        if seg.type == idaapi.SEG_CODE or seg.type == idaapi.SEG_DATA:
            yield from get_all_vtables_in(seg)

        seg = idaapi.get_next_seg(seg.start_ea)
