from collections import deque
from typing import Generator, List, Optional, Tuple

import ida_hexrays
import idaapi
import idautils
import idc

import symless.symbols as symbols
import symless.utils.utils as utils

""" Imports utilities """


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
        if name.startswith(import_name):
            import_ea = ea
            return False
        return True

    idaapi.enum_import_names(module, iterator)
    return import_ea


""" Names utilities """


def demangle(name: str, inf_attr=idc.INF_SHORT_DN) -> str:
    demangled = idaapi.demangle_name(name, idc.get_inf_attr(inf_attr))
    if demangled:
        return demangled

    return name


def demangle_ea(ea: int, inf_attr=idc.INF_SHORT_DN) -> str:
    return demangle(idaapi.get_name(ea), inf_attr)


# retrieve a name in the form "fct+offset"
def addr_friendly_name(ea: int) -> str:
    fct = idaapi.get_func(ea)
    if fct is None:
        return f"ea[0x{ea:x}]"

    offset = ea - fct.start_ea
    fct_name = symbols.full_method_name_from_signature(demangle(idaapi.get_short_name(fct.start_ea)))
    return "%s%s" % (fct_name, f"+{offset:x}" if offset != 0 else "")


""" Xrefs utilities """

# The following functions can be time-consuming when an address has numerous xref
# every xref has to be fetch using an API call


def get_references(address: int) -> List[int]:
    return [ref for ref in idautils.CodeRefsTo(address, 0)]


def get_data_references(address: int) -> List[int]:
    return [ref for ref in idautils.DataRefsTo(address)]


def get_all_references(address: int) -> set:
    crefs = get_references(address)
    drefs = get_data_references(address)
    return set(crefs + drefs)


""" Pointers utilities """


g_ptr_size = None


def get_ptr_size() -> int:
    global g_ptr_size
    g_ptr_size = (
        g_ptr_size if g_ptr_size else (8 if idaapi.inf_is_64bit() else (4 if idaapi.inf_is_32bit_or_higher else 2))
    )
    return g_ptr_size


def __dereference_pointer(addr: int, ptr_size: int) -> int:
    return idaapi.get_qword(addr) if ptr_size == 8 else idaapi.get_dword(addr)


def dereference_pointer(addr: int) -> int:
    return __dereference_pointer(addr, get_ptr_size())


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


""" Type utilities """


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
def get_local_type(name: str) -> Optional[idaapi.tinfo_t]:
    tinfo = idaapi.tinfo_t()
    if tinfo.get_named_type(idaapi.get_idati(), name):
        return tinfo
    return None


# convert a local variable forward ref into a real struct
def replace_forward_ref(tif: idaapi.tinfo_t):
    ord, tname = tif.get_ordinal(), tif.get_type_name()
    mudt = idaapi.udt_type_data_t()
    tif.create_udt(mudt)
    err = tif.set_numbered_type(None, ord, idaapi.NTF_REPLACE)
    if err != idaapi.TERR_OK:
        utils.g_logger.error(f'Could not convert forward ref to "{tname}" : {idaapi.tinfo_errstr(err)} ({err})')


# just a wrap around find_udm that returns BADADDR instead of -1
def find_udm_wrap(struc: idaapi.tinfo_t, udm: idaapi.udm_t) -> int:
    rc = struc.find_udm(udm, idaapi.STRMEM_OFFSET)
    return idaapi.BADADDR if rc in (-1, idaapi.BADADDR) else rc


""" Function utilities """


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
def set_function_argument(
    func_data: idaapi.func_type_data_t,
    index: int,
    typ: idaapi.tinfo_t,
    shift: int = 0,
    parent: Optional[idaapi.tinfo_t] = None,
    name: Optional[str] = None,
):
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
def new_func_data() -> idaapi.func_type_data_t:
    func_data = idaapi.func_type_data_t()

    # ret type to void
    ret_tinfo = idaapi.tinfo_t()
    ret_tinfo.create_simple_type(idaapi.BT_VOID)
    func_data.rettype = ret_tinfo

    # fastcall as default cc
    func_data.cc = idaapi.CM_CC_FASTCALL

    return func_data


# get the tinfo for a given function
def get_fct_type(fea: int, force_decompile: bool = False) -> Optional[idaapi.tinfo_t]:
    tinfo = idaapi.tinfo_t()
    hf = ida_hexrays.hexrays_failure_t()

    if (not force_decompile) and idaapi.get_tinfo(tinfo, fea):
        return tinfo

    utils.g_logger.info(f"Forcing decompilation of fct {fea:#x}")
    cfunc = ida_hexrays.decompile_func(idaapi.get_func(fea), hf, ida_hexrays.DECOMP_NO_WAIT)
    if cfunc is None:
        utils.g_logger.warning(f"Could not decompile fct {fea:#x}: {hf.str} ({hf.code})")
        return None

    if cfunc.get_func_type(tinfo):
        return tinfo

    utils.g_logger.error(f"No tinfo_t for fea {fea:#x}")
    return None


# get function type, create default one if none
def get_or_create_fct_type(fea: int) -> Tuple[idaapi.tinfo_t, idaapi.func_type_data_t]:
    func_tinfo = get_fct_type(fea)
    if func_tinfo is None:
        return (idaapi.tinfo_t(), new_func_data())

    func_data = idaapi.func_type_data_t()
    if func_tinfo.get_func_details(func_data):
        return (func_tinfo, func_data)

    return (func_tinfo, new_func_data())


# yields one instruction operands
def get_insn_ops(insn: idaapi.insn_t) -> Generator[idaapi.op_t, None, None]:
    i = 0
    while i < idaapi.UA_MAXOP and insn.ops[i].type != idaapi.o_void:
        yield insn.ops[i]
        i += 1


# get instruction's operands count
def get_len_insn_ops(insn: idaapi.insn_t) -> int:
    return len([i for i in get_insn_ops(insn)])


# cache our mbas with their special kregs
g_microcode_cache = dict()


# get the microcode for a given function
def get_func_microcode(func: idaapi.func_t, analyze_calls: bool = False) -> Optional[ida_hexrays.mba_t]:
    global g_microcode_cache
    if func.start_ea in g_microcode_cache:
        return g_microcode_cache[func.start_ea]

    # generate the function microcode
    mbr = ida_hexrays.mba_ranges_t(func)
    hf = ida_hexrays.hexrays_failure_t()
    mba: ida_hexrays.mba_t = ida_hexrays.gen_microcode(
        mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT, ida_hexrays.MMAT_PREOPTIMIZED
    )

    if not mba:
        utils.g_logger.error(f"Could generate mba for fct {func.start_ea:#x}: {hf.str} ({hf.code})")
        return None

    # build cfg and define blocks relations
    mba.build_graph()

    # resolve calls arguments and returns
    if analyze_calls:
        mba.analyze_calls(ida_hexrays.ACFL_GUESS)

    # only cache mba used by cpustate (without initial call analysis)
    else:
        g_microcode_cache[mba.entry_ea] = mba

    # allocate special kregs
    # used to pass result of inline minsns to parent minsn
    setattr(mba, "tmp_result_kregs", deque())
    for _ in range(8):
        mba.tmp_result_kregs.append(mba.alloc_kreg(get_ptr_size()))
    setattr(mba, "call_result_kreg", mba.alloc_kreg(get_ptr_size()))

    return mba


# analyze calls of given mba, make sure to have the correct args count for each
def mba_analyze_calls(mba: ida_hexrays.mba_t):
    global g_microcode_cache

    if mba.callinfo_built():  # already done
        return

    hf = ida_hexrays.hexrays_failure_t()

    # find all calls, decompile callees for accurate arguments count
    for i in range(mba.qty):
        mblock = mba.get_mblock(i)
        minsn = mblock.head

        while minsn:
            if minsn.is_unknown_call() and minsn.l.t == ida_hexrays.mop_v:
                fct = idaapi.get_func(minsn.l.g)
                if fct:
                    utils.g_logger.info(f"decompiling callee {fct.start_ea:#x} for accurate call info")
                    ida_hexrays.decompile_func(fct, hf, ida_hexrays.DECOMP_NO_WAIT)

            minsn = minsn.next

    # resolve call arguments (and ret) in mba
    mba.analyze_calls(ida_hexrays.ACFL_GUESS)


# get the microcode block containing the specified ea
def get_block_microcode(fct: idaapi.func_t, ea: int) -> Optional[Tuple[ida_hexrays.mblock_t, ida_hexrays.mba_t]]:
    # function microcode
    mba = get_func_microcode(fct)
    if not mba:
        return None

    # return containing block
    try:
        return (
            next(
                filter(
                    lambda b: (not (b.flags & ida_hexrays.MBL_FAKE)) and ea >= b.start and ea < b.end,
                    [mba.get_mblock(i) for i in range(mba.qty)],
                )
            ),
            mba,
        )
    except StopIteration:  # yes this can happen
        return None


# lift the instruction at ea into a micro instruction
# returns a MMAT_PREOPTIMIZED minsn
def get_ins_microcode(ea: int) -> Optional[ida_hexrays.minsn_t]:
    insn = idaapi.insn_t()
    rvec = idaapi.rangevec_t()
    hf = ida_hexrays.hexrays_failure_t()

    # get the instruction size
    insn_size = idaapi.decode_insn(insn, ea)
    if not insn_size:
        utils.g_logger.warning(f"no instruction found at {ea:#x}")
        return None

    # generate the mba
    rvec.push_back(idaapi.range_t(insn.ea, insn.ea + insn_size))
    mbr = ida_hexrays.mba_ranges_t(rvec)
    mba = ida_hexrays.gen_microcode(
        mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT | ida_hexrays.DECOMP_NO_FRAME, ida_hexrays.MMAT_PREOPTIMIZED
    )
    if not mba:
        utils.g_logger.error(f"Could not get minsn for ea {ea:#x}: {hf.str} ({hf.code})")
        return None

    # find the minsn in the mba
    # it should be the first instruction of the first non-fake block
    minsn = next(
        filter(lambda b: not (b.flags & ida_hexrays.MBL_FAKE), [mba.get_mblock(i) for i in range(mba.qty)])
    ).head

    return ida_hexrays.minsn_t(minsn)  # original is freed with mba


""" Misc """


# get root folder for local types, if supported
def get_local_types_folder() -> Optional[idaapi.dirtree_t]:
    try:
        return idaapi.get_std_dirtree(idaapi.DIRTREE_LOCAL_TYPES)
    except AttributeError:
        return None


# mcode_t values to microinstruction names
g_mcode_name = {
    getattr(ida_hexrays, mcode): mcode[2:] for mcode in filter(lambda y: y.startswith("m_"), dir(ida_hexrays))
}


# mopt_t values to operand type as str
g_mopt_name = [
    "mop_z",
    "mop_r",
    "mop_n",
    "mop_str",
    "mop_d",
    "mop_S",
    "mop_v",
    "mop_b",
    "mop_f",
    "mop_l",
    "mop_a",
    "mop_h",
    "mop_c",
    "mop_fn",
    "mop_p",
    "mop_sc",
]


# get instruction + operands representation
def insn_str_full(insn: ida_hexrays.minsn_t) -> str:
    return f"[{insn.dstr()}] = [{g_mcode_name[insn.opcode]} {', '.join([g_mopt_name[i.t] for i in (insn.l, insn.r, insn.d)])}]"
