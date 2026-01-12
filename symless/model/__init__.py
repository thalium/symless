from collections import defaultdict, deque
from typing import (
    Any,
    Collection,
    Dict,
    Generator,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
)

import ida_hexrays
import idaapi

import symless.allocators as allocators
import symless.cpustate.cpustate as cpustate
import symless.generation as generation
import symless.symbols as symbols
import symless.utils.ida_utils as ida_utils
import symless.utils.utils as utils
import symless.utils.vtables as vtables


# a field's type & potential value
class ftype_t:
    def __init__(self, value: cpustate.absop_t):
        self.value = value

    # should we propagate the field value when read
    def should_propagate(self) -> bool:
        return False

    # get value to use when propagating with cpustate
    def get_propagated_value(self) -> cpustate.absop_t:
        if self.should_propagate():
            return self.value
        return None

    def __eq__(self, other) -> bool:
        return isinstance(other, self.__class__) and self.value == other.value

    def __hash__(self) -> int:
        return hash((self.__class__, self.value))

    def __str__(self) -> str:
        return f"{self.__class__.__name__}:({self.value})"


# structure pointer type
class ftype_struc_t(ftype_t):
    def __init__(self, entry: "entry_t"):
        super().__init__(cpustate.sid_t(entry.id))
        self.entry = entry  # entry this field points to


# function pointer type
class ftype_fct_t(ftype_t):
    def __init__(self, value: cpustate.mem_t):
        super().__init__(value)

    def should_propagate(self) -> bool:
        return True


# default pointer type
class ftype_ptr_t(ftype_t):
    def __init__(self, value: cpustate.mem_t):
        super().__init__(value)

    def should_propagate(self) -> bool:
        return True


# entry point field
class field_t:
    def __init__(self, offset: int):
        self.offset = offset
        self.size: int = 0  # bitfield of possible sizes
        self.type: deque[ftype_t] = deque()  # list of affected types, in propagation's order

    # add a type to the field's possible types list
    def set_type(self, type: ftype_t):
        self.type.appendleft(type)  # record types in propagation order

    # get last affected type
    def get_type(self) -> Optional[ftype_t]:
        if len(self.type) == 0:
            return None
        return self.type[0]

    # add possible size
    def set_size(self, size: int):
        self.size |= size

    # get all possible field's sizes
    def get_size(self) -> Collection[int]:
        out = deque()
        for i in range(8):
            if self.size & (1 << i):
                out.append(pow(2, i))
        return out

    def __str__(self) -> str:
        return f"field_{self.offset:#x}:{self.size:#x}"


# records the data flow of a structure in a basic block
# since our data flow is flattened, loops & conditions are not taken into account
# then a basic block is an execution flow ended by a call or a ret
class block_t:
    def __init__(self, owner: "entry_t", id: int = 0):
        self.owner = owner
        self.fields: Dict[int, field_t] = dict()  # fields defined in the block & their types

        # block index in owner's blocks list
        self.id = id

        # structure's boundaries, from accessed fields
        self.max = 0
        self.min = 0

        # called ep following this block in the data flow
        self.callee: Optional[Tuple[int, "entry_t"]] = None

        # following & preceding block in the entrypoint flow
        self.next: Optional[block_t] = None
        self.previous: Optional[block_t] = None

    def has_callee(self) -> bool:
        return self.callee is not None

    def get_callee(self) -> Optional[Tuple[int, "entry_t"]]:
        return self.callee

    # set the called ep following this block & shift applied
    def set_callee(self, callee: "entry_t", shift: int):
        self.callee = (shift, callee)

    def get_owner(self) -> "entry_t":
        return self.owner

    # returns following block in the entrypoint
    def get_next(self) -> "block_t":
        if self.next is None:
            self.next = block_t(self.owner, self.id + 1)
            self.next.previous = self
        return self.next

    def has_field(self, offset: int) -> bool:
        return offset in self.fields

    # get field defined by this block
    def get_field(self, offset: int) -> field_t:
        return self.fields[offset]

    # get all fields
    def get_fields(self) -> Iterator[field_t]:
        return self.fields.values()

    # add / get existing field
    def add_field(self, offset: int, size: int) -> field_t:
        # accept negative offset, a field can be retrieved with a CONTAINING_RECORD()

        if offset not in self.fields:
            self.fields[offset] = field_t(offset)
        self.fields[offset].set_size(size)

        # change size upper boundary
        end = offset + size
        if end > self.max:
            self.max = end

        # change size lower boundary
        if offset < self.min:
            self.min = offset

        return self.fields[offset]

    # get the latest type for a field
    # scope: current block + following (called) entry
    def get_field_type(self, offset: int) -> Optional[ftype_t]:
        ftype = None
        if self.has_callee():
            shift, callee = self.get_callee()
            ftype = callee.get_field_type(offset - shift)

        return self.get_field(offset).get_type() if (ftype is None and self.has_field(offset)) else ftype

    def __eq__(self, other) -> bool:
        return isinstance(other, block_t) and other.id == self.id

    def __hash__(self) -> int:
        return self.id


# data flow entrypoints
# defines a structure's entry into the data flow
# records information defining a structure propagated from the given entrypoint
class entry_t:
    # this kind of ep is to be injected before or after state updates
    inject_before = False

    # this type of ep can have children
    can_ramificate = True

    def __init__(self, ea: int, sub_ea: int = 0):
        self.ea = ea  # entry address
        self.sub_ea = sub_ea  # index of the sub minsn the entry is for
        self.id = -1  # entry identifier

        # for entrypoints defining a structure (root ep)
        self.struc_id = -1

        # structure associated with this entrypoint
        # the structure we will use to type this ep
        self.struc: Optional[generation.structure_t] = None
        self.struc_shift = 0

        # data flow injection parameters
        self.to_analyze = True  # yet to analyze

        # list of operands accessing this ep fields
        # a single op might reference multiple fields (offsets), like in STP, STM arm insns
        self.operands: Dict[Tuple[int, int], Collection[int]] = defaultdict(list)  # (ea, reg_id) -> [offsets]

        # list of the entries that can precede this one in a data flow
        self.parents: Collection[Tuple[int, entry_t]] = deque()

        # list of entries we want to analyze following this one
        self.children: Collection[Tuple[int, entry_t]] = deque()

        # entrypoint size
        self.bounds: Optional[Tuple[int, int]] = None

        self.blocks: Optional[block_t] = None  # list of blocks composing this ep
        self.cblock: Optional[block_t] = None  # current active block

    # does the entry point defines a structure to be generated
    def is_root(self) -> bool:
        return self.struc_id >= 0

    def set_root(self, sid: int):
        self.struc_id = sid

    def has_structure(self) -> bool:
        return self.struc is not None

    def set_structure(self, shift: int, struc: "generation.structure_t"):
        self.struc = struc
        self.struc_shift = shift
        struc.has_xrefs |= self.has_operands()

    # get the structure associated with the entry
    def get_structure(self) -> Tuple[int, "generation.structure_t"]:
        return (self.struc_shift, self.struc)

    # return the function containing this ep
    def get_function(self) -> int:
        return idaapi.BADADDR

    # get all the structures that flow through this ep
    def get_flow(self) -> Collection[Tuple[int, "generation.structure_t"]]:
        flow = set()
        if self.is_root():
            flow.add(self.get_structure())
        for shift, parent in self.get_parents():
            flow.update([(shift + s_shift, s) for s_shift, s in parent.get_flow()])
        return flow

    def add_field(self, offset: int, size: int) -> field_t:
        return self.cblock.add_field(offset, size)

    # get field at given offset
    def get_field(self, offset: int) -> Optional[field_t]:
        return self.cblock.get_field(offset)

    # get the latest type for a field
    # scope: current entry (previous block & callees), at current state (not done analyzing)
    def get_field_type(self, offset: int) -> Optional[ftype_t]:
        ftype = None
        current = self.cblock
        while ftype is None and current is not None:
            ftype = current.get_field_type(offset)
            current = current.previous

        return ftype

    # get ep boundaries, min & max access on ep
    def get_boundaries(self) -> Tuple[int, int]:
        if self.bounds is None:
            lower, upper = 0, 0

            # ep own boundaries
            current = self.blocks
            while current is not None:
                lower = min(lower, current.min)
                upper = max(upper, current.max)
                current = current.next

            # boundaries from ep children
            for off, child in self.get_children(True):
                ci, ca = child.get_boundaries()
                lower = min(lower, ci + off)
                upper = max(upper, ca + off)

            self.bounds = (lower, upper)

        return self.bounds

    # associated accessed operand with this ep
    def add_operand(self, ea: int, off: int, regid: int):
        self.operands[(ea, regid)].append(off)

    def get_operands(self) -> Generator[Tuple[int, int, Collection[int]], None, None]:
        for (ea, regid), offs in self.operands.items():
            yield (ea, regid, offs)

    def has_operands(self) -> bool:
        return len(self.operands) > 0

    # does the given node precede this node in the data flow
    def has_parent(self, parent: "entry_t") -> bool:
        return self == parent or any([p.has_parent(parent) for _, p in self.get_parents()])

    # add parent with given shift
    def add_parent(self, parent: "entry_t", shift: int) -> bool:
        if parent.has_parent(self):  # loop check
            return False

        if (shift, parent) not in self.parents:  # duplicate check
            self.parents.append((shift, parent))
        return True

    # add an entrypoint following this one in the data flow
    def add_child(self, child: "entry_t", shift: int) -> bool:
        if not child.add_parent(self, shift):
            return False

        if (shift, child) not in self.children:
            self.children.append((shift, child))
        return True

    # end the current block, with a call
    # the callee represents an ep to be processed after the current block and before the next one
    def end_block(self, callee: "entry_t", shift: int) -> bool:
        if not callee.add_parent(self, shift):
            return False

        self.cblock.set_callee(callee, shift)
        self.cblock = self.cblock.get_next()
        return True

    # get node's parents
    # yields (shift, parent)
    def get_parents(self) -> Generator[Tuple[int, "entry_t"], None, None]:
        for off, p in self.parents:
            yield (off, p)

    # get node's children
    # if all is set, returns following children + end blocks callee children
    # else only returns following children
    def get_children(self, all: bool = False) -> Generator[Tuple[int, "entry_t"], None, None]:
        if all:
            assert self.blocks is not None

            current = self.blocks
            while current.next is not None:
                yield current.get_callee()
                current = current.next

        for off, c in self.children:
            yield (off, c)

    # get distance to given child
    # assume self is parent of child
    def distance_to(self, child: "entry_t") -> int:
        q = deque()

        q.append((child, 0))
        while len(q) > 0:
            current, distance = q.popleft()
            if current == self:
                return distance

            for _, p in current.get_parents():
                q.append((p, distance + 1))

        raise Exception(f"{self.entry_id()} is not a parent of {child.entry_id()}")

    # inject entrypoint on given state
    # return True if the ep had to be analyzed
    def inject(self, state: cpustate.state_t, reset: bool = True) -> bool:
        if reset:
            self.reset()
        had_to = self.to_analyze
        self.to_analyze = False  # is beeing analyzed
        return had_to

    # reset non-cumulative states when re-propagating
    def reset(self):
        # reset blocks
        self.blocks = block_t(self)
        self.cblock = self.blocks
        utils.g_logger.debug(f"Resetting entry {self.entry_id()}")

    # get unique key identifying the ep from others
    # to be implemented by heirs
    def get_key(self) -> Any:
        raise Exception(f"{self.__class__} does not implement method get_key")

    # find name of the structure associated to this entry point
    # using symbols information
    # returns name, relevance (the least, the more relevant)
    def find_name(self) -> Tuple[Optional[str], int]:
        return None, 0

    def entry_header(self) -> str:
        return "Entry[sid=%d], ea: 0x%x, [%s]" % (
            self.id,
            self.ea,
            ("TO_ANALYZE" if self.to_analyze else "ANALYZED"),
        )

    def entry_id(self) -> str:
        return f"ep_0x{self.ea:x}"

    def __eq__(self, other) -> bool:
        return isinstance(other, entry_t) and other.id == self.id

    def __hash__(self) -> int:
        return self.id

    def __str__(self) -> str:
        out = "%s\n" % self.entry_header()
        out += f"\t| Parents: ({', '.join([str(i.id) for i in self.get_parents()])})\n"

        if len(self.operands) > 0:
            out += "\t| Operands:\n"
            for ea, regid, offs in self.get_operands():
                for off in offs:
                    out += f"\t\t{ida_utils.addr_friendly_name(ea)}, ea: 0x{ea:x}, reg {idaapi.get_reg_name(regid,8)}({regid:#x}), off {off:#x}\n"

        if len(self.children) > 0:
            out += "\t| Children:\n"
            for offset, child in self.children:
                out += f"\t\tentry[sid={child.id}], off: 0x{offset:x}, ea: 0x{child.ea:x}\n"

        return out


# travel the flows of nodes from given entrypoint
# yields (flow root, node, shift)
def flow_from_root(entry: entry_t, all_roots: bool = True) -> Generator[Tuple[entry_t, block_t, int], None, None]:
    roots: Collection[Tuple[int, entry_t]] = deque()
    roots.append((0, entry))

    while len(roots) > 0:
        rshift, root = roots.pop()
        if all_roots:
            roots.extend([(i + rshift, j) for i, j in root.get_children()])

        blocks: Collection[int, block_t] = deque()
        blocks.append((rshift, root.blocks))

        while len(blocks) > 0:
            bshift, node = blocks.pop()
            yield root, node, bshift

            # record next block for latter
            if node.next is not None:
                blocks.append((bshift, node.next))

            # process blocks from direct function call before
            if node.has_callee():
                cshift, callee = node.get_callee()
                blocks.append((bshift + cshift, callee.blocks))

                # childrens are not in this direct flow (ex: virtual method recorded from vtable load)
                # process them as differents roots
                if all_roots:
                    roots.extend([(bshift + cshift + i, j) for i, j in callee.get_children()])


# entrypoint as a method's argument
class arg_entry_t(entry_t):
    inject_before = True

    def __init__(self, ea: int, index: int):
        super().__init__(ea, -1)
        self.index = index

    def get_function(self) -> int:
        return self.ea

    def find_name(self) -> Tuple[Optional[str], int]:
        if self.index != 0:  # TODO use fct arguments types to find names of arguments that are not 'this'
            return None, 0

        fct_name = ida_utils.demangle_ea(self.ea)
        return symbols.get_classname_from_ctor(fct_name), 1

    def inject(self, state: cpustate.state_t) -> bool:
        had_to = super().inject(state, False)

        vdloc = state.fct.get_argloc(self.index)
        state.set_var_from_loc(vdloc, cpustate.sid_t(self.id))

        return had_to

    def get_key(self) -> int:
        return self.index

    def entry_id(self) -> str:
        return f"ep_0x{self.ea:x}_arg{self.index}"

    def entry_header(self) -> str:
        return "Entry[sid=%d], arg %d of %s (0x%x), [%s]" % (
            self.id,
            self.index,
            ida_utils.addr_friendly_name(self.ea),
            self.ea,
            ("TO_ANALYZE" if self.to_analyze else "ANALYZED"),
        )


# entry point in a variable (a micro operand)
# for destination operands (inject_before == False)
class dst_var_entry_t(entry_t):
    def __init__(self, ea: int, sub_ea: int, fct_ea: int, mop: ida_hexrays.mop_t):
        super().__init__(ea, sub_ea)
        self.mop = ida_hexrays.mop_t(mop)  # copy or it gets freed
        assert self.mop.t in (ida_hexrays.mop_r, ida_hexrays.mop_S)

        if self.mop.t == ida_hexrays.mop_r:
            self.key = ida_hexrays.get_mreg_name(self.mop.r, ida_utils.get_ptr_size())
        else:
            self.key = f"stk:#{self.mop.s.off:x}"

        self.fct_ea = fct_ea

    def get_function(self) -> int:
        return self.fct_ea

    def inject(self, state: cpustate.state_t) -> bool:
        had_to = super().inject(state)
        state.set_var_from_mop(self.mop, cpustate.sid_t(self.id))
        return had_to

    def get_key(self) -> str:
        return self.key

    def entry_id(self) -> str:
        return f"ep_0x{self.ea:x}_{self.get_key()}"

    def entry_header(self) -> str:
        return "Entry[sid=%d], %s at ea: 0x%x(%s), [%s]" % (
            self.id,
            self.get_key(),
            self.ea,
            ida_utils.addr_friendly_name(self.ea),
            ("TO_ANALYZE" if self.to_analyze else "ANALYZED"),
        )


# entry point in a register
# as a src operand (inject_before == True)
class src_reg_entry_t(dst_var_entry_t):
    # inject_before needs to be a static member
    # because of its use in get_entry_by_key()
    # thus two reg_entry_t classes are required
    inject_before = True


# entry point as a value read from a structure
# can be used to propagate a structure ptr written & read from a structure
class read_entry_t(dst_var_entry_t):
    can_ramificate = False

    def __init__(self, ea: int, sub_ea: int, fct_ea: int, mop: ida_hexrays.mop_t, source: entry_t, off: int):
        super().__init__(ea, sub_ea, fct_ea, mop)

        # source ep & offset this ep was read from
        self.src = source
        self.src_off = off

    def entry_id(self) -> str:
        return f"ep_rd_0x{self.ea:x}_{self.get_key()}"

    def add_parent(self, parent: "entry_t", shift: int) -> bool:
        raise Exception("read_entry_t are not meant to be linked with parents")


# entry point as an allocation with known size
class alloc_entry_t(dst_var_entry_t):
    def __init__(self, ea: int, sub_ea: int, size: int, mba: ida_hexrays.mba_t):
        super().__init__(ea, sub_ea, mba.entry_ea, ida_hexrays.mop_t(mba.call_result_kreg, ida_utils.get_ptr_size()))
        self.size = size

    # retrieve name from factory function
    # this is not an accurate name for a structure, and is to be used as a last chance name
    def find_name(self) -> Tuple[Optional[str], int]:
        fct = idaapi.get_func(self.ea)
        if fct is None:
            utils.g_logger.error(f"No function for entry {self.entry_id()}, this should not happen")
            return None, 0

        # do not use 'sub_' function names
        if not symbols.has_relevant_name(fct.start_ea):
            return None, 0

        fct_name = symbols.method_name_from_signature(ida_utils.demangle_ea(fct.start_ea))
        return f"struc_{fct_name}", 3

    def add_field(self, offset: int, size: int) -> field_t:
        if offset < 0 or offset + size > self.size:
            return False

        return super().add_field(offset, size)


# constant root entry
# define a known structure we do not need to build on the way
class cst_entry_t(entry_t):
    def __init__(self, ea: int):
        super().__init__(ea)

        self.to_analyze = False

    # do not record accessed fields
    def add_field(self, offset: int, size: int) -> None:
        return None

    # a root has no parents
    def has_parent(self, parent: entry_t) -> bool:
        return False

    def add_parent(self, parent: entry_t, shift: int) -> bool:
        return False

    def end_block(self, callee: entry_t, shift: int) -> bool:
        return False

    def inject(self, state: cpustate.state_t) -> bool:
        raise Exception(f"{self.entry_id()} is not to be injected in the data flow")


# vtable root entry
class vtbl_entry_t(cst_entry_t):
    def __init__(self, vtbl: vtables.vtable_t):
        super().__init__(vtbl.ea)
        self.vtbl = vtbl
        self.reset()  # add default block

        # make fields
        ptr_size = ida_utils.get_ptr_size()
        for i, (fea, _) in enumerate(vtbl.get_members()):
            field = entry_t.add_field(self, i * ptr_size, ptr_size)
            field.set_type(ftype_fct_t(cpustate.mem_t(fea, fea, ptr_size)))

    # get most derived between self and other
    def get_most_derived(self, other: "vtbl_entry_t") -> "vtbl_entry_t":
        if self.vtbl.get_most_derived(other.vtbl) == self.vtbl:
            return self
        return other

    def get_key(self) -> Any:  # ea is enough to discriminate vtables
        return None

    def find_name(self) -> Tuple[Optional[str], int]:
        return symbols.get_vtable_name_from_ctor(self.ea), 0

    def entry_id(self) -> str:
        return f"ep_0x{self.ea:x}_vtbl"

    def entry_header(self) -> str:
        return f"vftable {ida_utils.demangle_ea(self.ea)}"


# records all entrypoints
class entry_record_t:
    g_next_sid = -1

    def __init__(self):
        self.entries_per_sid: List[entry_t] = list()  # entry per sid

        # sorted entries, by ea for quick access
        # & by inject_before / inject_after
        self.entries_per_ea: dict[Tuple[int, int, bool], Collection[entry_t]] = defaultdict(deque)

    # next entry point id
    def next_id(self) -> int:
        return len(self.entries_per_sid)

    def structures_count(self) -> int:
        return entry_record_t.g_next_sid + 1

    # add an entrypoint to the graph
    def add_entry(self, entry: entry_t, as_root: bool = False, inc_sid: bool = True) -> entry_t:
        existing = self.get_entry_by_key(entry.ea, entry.sub_ea, entry.__class__, entry.get_key())
        if existing is not None:
            return existing

        key = (entry.ea, entry.sub_ea, entry.__class__.inject_before)
        self.entries_per_ea[key].append(entry)

        entry.id = self.next_id()
        self.entries_per_sid.append(entry)

        if as_root:
            entry_record_t.g_next_sid += int(inc_sid)
            entry.set_root(entry_record_t.g_next_sid)

        return entry

    # add an entry to the graph, as a child of another entry
    def add_entry_as_child(self, parent: entry_t, child: entry_t, shift: int, block_end: bool) -> Optional[entry_t]:
        # check if parent can have children
        if not parent.__class__.can_ramificate:
            return None

        effective = self.add_entry(child)

        if block_end:
            parent.end_block(effective, shift)
        else:
            parent.add_child(effective, shift)

        return effective

    # remove an entry from the graph, and its successors
    def remove_entry(self, entry: entry_t):
        # entry should not have any parents
        assert len(entry.parents) == 0

        for shift, child in entry.get_children(True):
            child.parents.remove((shift, entry))
            if len(child.parents) == 0:
                self.remove_entry(child)

        self.entries_per_ea[(entry.ea, entry.sub_ea, entry.__class__.inject_before)].remove(entry)
        self.entries_per_sid[entry.id] = None

    # all entries to inject at given ea
    def get_entries_at(self, ea: int, sub_ea: int, inject_before: bool) -> Collection[entry_t]:
        return self.entries_per_ea.get((ea, sub_ea, inject_before), tuple())

    # entry by sid
    def get_entry_by_id(self, sid: int) -> Optional[entry_t]:
        if sid < 0 or sid >= len(self.entries_per_sid):
            return None
        return self.entries_per_sid[sid]

    # entry by ea, class & unique key identifier
    def get_entry_by_key(self, ea: int, sub_ea: int, cls: type, key: Any = None) -> Optional[entry_t]:
        eakey = (ea, sub_ea, cls.inject_before)
        if eakey not in self.entries_per_ea:
            return None

        c = filter(
            lambda e: isinstance(e, cls) and e.get_key() == key,
            self.entries_per_ea[eakey],
        )

        try:
            return next(c)
        except StopIteration:
            return None

    def get_entries(self, analyzed: bool = True) -> Generator[entry_t, None, None]:
        for entry in self.entries_per_sid:
            if entry is not None and not (analyzed and entry.to_analyze):
                yield entry

    # yield all unexplored entrypoints
    # TODO: yield from most interesting function to less (fct having the most entrypoints)
    def next_to_analyze(self) -> Generator[entry_t, None, None]:
        current_len = len(self.entries_per_sid)
        for i in range(current_len):
            if self.entries_per_sid[i].to_analyze:
                yield self.entries_per_sid[i]

    def __str__(self) -> str:
        out = ""
        for entry in self.entries_per_sid:
            out += f"{str(entry)}\n"
        return out


# information about a function's prototype
class prototype_t:
    def __init__(self, ea: int):
        self.ea = ea

        # structure returned by function
        self.ret: Optional[entry_t] = None

        # is a virtual method
        self.virtual = False

    def set_ret(self, ret: entry_t):
        self.ret = ret

    def get_ret(self) -> Optional[entry_t]:
        return self.ret

    def set_virtual(self):
        self.virtual = True

    def is_virtual(self) -> bool:
        return self.virtual

    def __eq__(self, other: object) -> bool:
        return isinstance(other, prototype_t) and self.ea == other.ea


# global model
# groups information gathered by the analysis
class context_t:
    # init from a list of entrypoints and propagation context
    def __init__(self, entries: entry_record_t, allocators: Set[allocators.allocator_t]):
        self.allocators = allocators  # all registered allocators
        self.functions: Dict[int, prototype_t] = dict()  # ea -> prototype_t
        self.graph = entries  # entrypoints tree hierarchy

        # information gathered by data flow
        # is to be deleted once propagation is done
        self.dflow_info: Optional[cpustate.dflow_ctrl_t]

        # propagation context depth
        self.follow_calls = True

        # dive into callee decision
        self.dive_in: bool = False

    def get_function(self, ea: int) -> prototype_t:
        if ea not in self.functions:
            self.functions[ea] = prototype_t(ea)
        return self.functions[ea]

    def get_functions(self) -> Collection[prototype_t]:
        return self.functions.values()

    def get_entrypoints(self) -> entry_record_t:
        return self.graph

    def get_allocators(self) -> Set[allocators.allocator_t]:
        return self.allocators

    def can_follow_calls(self) -> bool:
        return self.follow_calls

    def set_follow_calls(self, follow: bool):
        self.follow_calls = follow
