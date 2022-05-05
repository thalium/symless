import idaapi
import idc
import idautils

import collections

import symless.cpustate.cpustate as cpustate

''' Imports utilities '''

def get_import_module_index(name: str) -> int:
    for i in range(idaapi.get_import_module_qty()):
        if idaapi.get_import_module_name(i) == name:
            return i
    return None

# Get ea of given import, from given module
def get_import_from_module(module: int, import_name: str) -> int:
    import_ea = None

    def iterator(ea, name, ord):
        nonlocal import_ea, import_name
        if name == import_name:
            import_ea = ea
            return False
        return True

    idaapi.enum_import_names(module, iterator)
    return import_ea


''' Names utilities '''

def demangle(name: str, inf_attr=idc.INF_SHORT_DN) -> str:
    if not name:
        return name

    demangled = idaapi.demangle_name(name, idc.get_inf_attr(inf_attr))
    if demangled:
        return demangled

    return name


''' Xrefs utilities '''

# The following functions can be time-consuming when an address has numerous xref
# every xref has to be fetch using an API call

def get_references(address: int) -> [int]:
    return [ref for ref in idautils.CodeRefsTo(address, 0)]

def get_data_references(address: int) -> [int]:
    return [ref for ref in idautils.DataRefsTo(address)]

def get_all_references(address: int) -> set:
    crefs = get_references(address)
    drefs = get_data_references(address)
    return set(crefs + drefs)


''' Pointers utilities '''

def get_ptr_size():
    return 8 if idaapi.get_inf_structure().is_64bit() else 4

def __dereference_pointer(addr: int, ptr_size: int) -> int:
    return idaapi.get_qword(addr) if ptr_size == 8 else idaapi.get_dword(addr)

def dereference_pointer(addr: int) -> int:
    return __dereference_pointer(addr, get_ptr_size())

def dereference_function_ptr(addr: int, ptr_size: int) -> bool:
    fea = __dereference_pointer(addr, ptr_size)
    func = idaapi.get_func(fea)
    if func is None or func.start_ea != fea:  # addr is a function entry point
        return None
    return fea

# get size bytes from given ea, if ea is initialized with a value
def get_nb_bytes(ea: int, size: int) -> int:
    if not idaapi.is_loaded(ea):
        return None

    if size == 8:
        return idaapi.get_qword(ea)
    if size == 4:
        return idaapi.get_dword(ea)
    if size == 2:
        return idaapi.get_word(ea)

    return idaapi.get_byte(ea)

# return true if data at given ea & size has a value
def is_data_initialized(ea: int, size: int) -> bool:

    # assume there can not be uninitialized bytes between data start & end
    return idaapi.is_loaded(ea) and idaapi.is_loaded(ea + size - 1)


''' Vftable utilities '''

# can instruction at given ea load a vtable
def is_vtable_load(ea: int) -> bool:
    if idaapi.get_func(ea) is None:
        return False

    insn = idaapi.insn_t()
    if idaapi.decode_insn(insn, ea) == 0:
        return False

    if insn.itype not in [idaapi.NN_lea, idaapi.NN_mov] or insn.ops[0].type not in (idaapi.o_reg, idaapi.o_phrase, idaapi.o_displ):
        return False

    # type 1: lea/mov rax, vtbl
    # type 2: lea/mov rax, [eax + vtbl_offset] (PIE case)
    return insn.ops[1].type in [idaapi.o_mem, idaapi.o_displ, idaapi.o_imm]
 
# is vtable loaded at addr load stored later in a struct disp
# returns the stored value if it is the case
# TODO: miss mv [rax + rcx*2 + 16], rbx, even if we won't use it
def is_vtable_stored(load: int, loaded: int) -> int:
    # following is: mov [rcx + n], rax
    bb = get_bb(load)
    if bb is None:
        return idaapi.BADADDR

    bb.start_ea = load

    state = cpustate.state_t()
    state.reset_arguments(cpustate.get_abi())
    for insn in cpustate.read_basic_block_instructions(bb):
        cpustate.process_instruction(state, insn)

        if len(state.writes) > 0 and isinstance(state.writes[0].src, cpustate.mem_t):
            actual_loaded = state.writes[0].src.addr
            if loaded == actual_loaded:
                return state.writes[0].src.get_val()

    return idaapi.BADADDR

# is given ea a vtable or a vtable ref (.got)
# returns effective vtable address
def is_vtable_start(ea: int) -> int:
    if not idaapi.is_loaded(ea):
        return idaapi.BADADDR

    for xref in get_data_references(ea):

        # code loads the ea into a register
        if not is_vtable_load(xref):
            return idaapi.BADADDR

        # value from ea is stored into a struct
        stored_value = is_vtable_stored(xref, ea)
        if stored_value == idaapi.BADADDR:
            continue # continue because we miss the "mov [rax + rcx*n], vtbl" instructions

        # stored addr points to a functions ptrs array
        if vtable_size(stored_value) == 0:
            return idaapi.BADADDR

        return stored_value

    return idaapi.BADADDR

# Returns function ea if function at given addr is in vtable, None otherwise
def is_in_vtable(start_addr: int, addr: int, ptr_size: int):
    fea = dereference_function_ptr(addr, ptr_size)
    if fea is None:
        return None

    if addr == start_addr:
        return fea

    if (
        idaapi.get_first_dref_to(addr) != idaapi.BADADDR
        or idaapi.get_first_cref_to(addr) != idaapi.BADADDR
    ):  # data is referenced, not part of the vtable
        return None

    return fea

# yield all members of given vtable
def vtable_members(addr: int):
    ptr_size = get_ptr_size()

    current = addr
    fea = is_in_vtable(addr, current, ptr_size)
    while fea is not None:
        yield fea
        current += ptr_size
        fea = is_in_vtable(addr, current, ptr_size)

def vtable_size(addr: int) -> int:
    vtbl = [fea for fea in vtable_members(addr)]
    return len(vtbl) * get_ptr_size()

# scans given segment for vtables
# WARN: will not return vtables only used at virtual bases (vbase)
def get_all_vtables_in(seg: idaapi.segment_t):
    # print("INFO: scanning segment %s[%x, %x] for vtables" % (idaapi.get_segm_name(seg), seg.start_ea, seg.end_ea))

    current = seg.start_ea
    while current != idaapi.BADADDR and current < seg.end_ea:

        # do not cross functions
        chunk = idaapi.get_fchunk(current)
        if chunk is not None:
            current = chunk.end_ea
            continue

        # references a vtable ?
        effective_vtable = is_vtable_start(current)
        if effective_vtable != idaapi.BADADDR:
            yield (current, effective_vtable)

        current = idaapi.next_head(current, seg.end_ea)

# scans code segments for vtables
def get_all_vtables():
    seg = idaapi.get_first_seg()
    while seg is not None:

        # search for vtables in .data and .text segments
        if seg.type == idaapi.SEG_CODE or seg.type == idaapi.SEG_DATA:
            for i in get_all_vtables_in(seg):
                yield i

        seg = idaapi.get_next_seg(seg.start_ea)

# vtable ea from already existing vtable struc
def get_vtable_ea(vtable: idaapi.struc_t) -> (int, str):
    name = idaapi.get_struc_name(vtable.id)
    if not name.endswith(idaapi.VTBL_SUFFIX):
        return idaapi.BADADDR, name

    return idaapi.get_first_dref_to(vtable.id), name

# get vtable struc typing the given vtable ea
def get_ea_vtable(ea: int) -> idaapi.struc_t:
    tinfo = idaapi.tinfo_t()
    if not idaapi.get_tinfo(tinfo, ea):
        return None
    return struc_from_tinfo(tinfo)


''' Type utilities '''

# get basic type
def get_basic_type(type: int) -> idaapi.tinfo_t:
    tinfo = idaapi.tinfo_t()
    tinfo.create_simple_type(type)
    return tinfo

# returns void* tinfo_t
def void_ptr() -> idaapi.tinfo_t:
    tinfo = get_basic_type(idaapi.BT_VOID)
    tinfo.create_ptr(tinfo)
    return tinfo

# local type by name
def get_local_type(name: str) -> idaapi.tinfo_t:
    tinfo = idaapi.tinfo_t()
    tinfo.get_named_type(idaapi.get_idati(), name)
    return tinfo

# tinfo to struc, by name correspondance
def struc_from_tinfo(tinfo: idaapi.tinfo_t) -> idaapi.struc_t:
    sid = idaapi.get_struc_id(tinfo.get_type_name())
    if sid == idaapi.BADADDR:
        return None

    return idaapi.get_struc(sid)


''' Function utilities '''

# creates funcarg_t type
def make_function_argument(typ: idaapi.tinfo_t, name: str = "") -> idaapi.funcarg_t:
    farg = idaapi.funcarg_t()
    farg.type = typ
    farg.name = name
    return farg

# shift pointer
def shift_ptr(ptr: idaapi.tinfo_t, parent: idaapi.tinfo_t, shift: int):
    if shift == 0:
        return

    ptr_data = idaapi.ptr_type_data_t()
    if ptr.get_ptr_details(ptr_data):
        ptr_data.taptr_bits |= idaapi.TAPTR_SHIFTED
        ptr_data.delta = shift
        ptr_data.parent = parent
        ptr.create_ptr(ptr_data, idaapi.BT_PTR)

# add argument to function + shift ptr argument
def set_function_argument(func_data: idaapi.func_type_data_t, index: int, typ: idaapi.tinfo_t, shift: int = 0, parent: idaapi.tinfo_t = None, name = None):
    while index > func_data.size():
        func_data.grow(make_function_argument(void_ptr(), f"arg_{func_data.size()}"))

    # apply __shifted
    shift_ptr(typ, parent, shift)

    if name is None:
        name = f"arg_{index}"

    arg = make_function_argument(typ, name)
    if index == func_data.size():
        func_data.grow(arg)
    else:
        func_data[index] = arg

# creates a new valid func_type_data_t object
def new_func_data(cc: int = idaapi.CM_CC_UNKNOWN) -> idaapi.func_type_data_t:
    func_data = idaapi.func_type_data_t()

    # ret type to void
    ret_tinfo = idaapi.tinfo_t()
    ret_tinfo.create_simple_type(idaapi.BT_VOID)
    func_data.rettype = ret_tinfo

    # calling convention
    func_data.cc = cc

    return func_data

# get basic block containing ea
def get_bb(ea: int) -> idaapi.range_t:
    func = idaapi.get_func(ea)
    if func is None:
        return None

    flow = idaapi.qflow_chart_t()
    flow.create("", func, func.start_ea, func.end_ea, idaapi.FC_NOEXT)
    for i in range(flow.size()):
        if ea >= flow[i].start_ea and ea < flow[i].end_ea:
            return idaapi.range_t(flow[i].start_ea, flow[i].end_ea)

    return None