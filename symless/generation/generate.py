from typing import Dict, Tuple

import idaapi
import idautils
import idc

import symless.allocators as allocators
import symless.existing as existing
import symless.model.entrypoints as entrypoints
import symless.symbols as symbols
import symless.utils.ida_utils as ida_utils
from symless.generation import *

# folder in local types listing, to store symless generated types
STRUC_DIR = "Symless"


# make symless structures directory
def make_structures_dir():
    root = ida_utils.get_local_types_folder()
    if root is None:
        return

    err = root.mkdir(STRUC_DIR)
    if err not in (idaapi.DTE_OK, idaapi.DTE_ALREADY_EXISTS):
        utils.g_logger.error(f'Could not create {STRUC_DIR} local types folder: "{root.errstr(err)}"')


# create an empty IDA structure used to contain given struc
def make_IDA_structure(struc: structure_t):
    if struc.ida_tid != idaapi.BADADDR:
        return

    name = struc.get_name()

    # check for existing struc
    ida_tid = struc.find_existing()
    if ida_tid != idaapi.BADADDR:
        utils.g_logger.info(f'Re-using existing structure (tid {ida_tid:#x}) for model "{name}"')
        return

    # create new structure
    struc.set_existing(idc.add_struc(idaapi.BADADDR, name, False))
    if struc.ida_tid == idaapi.BADADDR:
        utils.g_logger.error(f'Could not create empty structure "{name}"')
        return

    # move it to symless folder
    root = ida_utils.get_local_types_folder()
    if root is None:
        return

    err = root.rename(name, f"{STRUC_DIR}/{name}")
    if err != idaapi.DTE_OK:
        utils.g_logger.warning(f'Could not move structure "{name}" into {STRUC_DIR} directory: "{root.errstr(err)}"')


# do we want to type IDA base with given entry data
def should_type_entry(entry: entrypoints.entry_t, ctx: entrypoints.context_t) -> bool:
    # root is always right
    if entry.is_root():
        return True

    shift, struc = entry.get_structure()
    if not struc.relevant():
        return False  # structure will not be generated

    struc_tif = struc.find_tinfo()

    # do not overwrite typing set by user on operands
    # TODO we should only check the operand we will type
    # for now check all operands on the instructions about to be typed
    # assume only one operand per instruction can be typed with a struc path (not sure if always true)
    for ea, _, _ in entry.get_operands():
        for n in range(idaapi.UA_MAXOP):
            # operand was typed with a different structure than ours, stop
            if existing.get_op_stroff(ea, n) not in (idaapi.BADADDR, struc_tif.get_tid()):
                return False

    # always type with vtbl, no matter its size
    if isinstance(struc, vtable_struc_t):
        return True

    # arguments entries special case
    if isinstance(entry, entrypoints.arg_entry_t):
        # always type virtual functions
        fct = ctx.get_function(entry.ea)
        if fct.is_virtual():
            return True

        # avoid other shifted ptr arguments
        if shift != 0:
            return False

        # TODO: do not type when arg is already typed with different struc

    # do not type entries that do not represent a structure
    lower, upper = entry.get_boundaries()
    if lower == 0 and upper <= ida_utils.get_ptr_size():
        return False

    return True


# update given function's returned type with the given entry
def type_function_return(fct: entrypoints.prototype_t, entry: entrypoints.entry_t):
    # entry is not returned, exit
    if fct.get_ret() != entry:
        return

    shift, struc = entry.get_structure()

    # avoid prone to error shifted pointers
    if shift != 0:
        return

    func_tinfo, func_data = ida_utils.get_or_create_fct_type(fct.ea)
    if not existing.should_arg_type_be_replaced(func_data.rettype):
        return

    tinfo = struc.find_ptr_tinfo()
    func_data.rettype = tinfo

    if func_tinfo.create_func(func_data):
        idaapi.apply_tinfo(fct.ea, func_tinfo, idaapi.TINFO_DEFINITE)

        utils.g_logger.info(f"Typing return of fct_0x{fct.ea:x} with {tinfo}")


# update function's type with given arg entrypoint
def type_function_argument(fct: entrypoints.prototype_t, arg: entrypoints.entry_t):
    if not isinstance(arg, entrypoints.arg_entry_t):
        return

    idx = arg.index

    func_tinfo, func_data = ida_utils.get_or_create_fct_type(fct.ea)
    if idx >= func_data.size():
        return

    # do not replace existing (complex) type
    if not existing.should_arg_type_be_replaced(func_data[idx].type):
        return

    shift, struc = arg.get_structure()
    ida_utils.set_function_argument(
        func_data,
        idx,
        struc.find_ptr_tinfo(),
        shift,
        struc.find_tinfo(),
        "this" if idx == 0 else None,
    )

    if not func_tinfo.create_func(func_data):
        utils.g_logger.error(f"Could not type arg_{idx} of fct_0x{fct.ea:x} with {arg.entry_id()}")
        return

    idaapi.apply_tinfo(fct.ea, func_tinfo, idaapi.TINFO_DEFINITE)

    utils.g_logger.info(f"Typing fct_0x{fct.ea:x} arg_{idx} with {struc.get_name()} shifted by 0x{shift:x}")


# which op of the given insn should we type with a structure path
# for given reg and given field offset
# returns op and shift to apply
def find_op_for_stroff(insn: idaapi.insn_t, regid: int, off: int) -> Tuple[Optional[idaapi.op_t], int]:
    for op in ida_utils.get_insn_ops(insn):
        # disp/phrase with regid for base register, this is what we want to type
        # we assume they should not be more than one disp/phrase op per insn
        if op.type in (idaapi.o_phrase, idaapi.o_displ) and op.phrase == regid:
            # compute shift to apply to type with member at given offset
            displ = op.addr if op.type == idaapi.o_displ else 0  # signed int32
            shift = utils.to_c_integer(off - displ, 4)

            return (op, shift)

        # immediate operand, preceded regid
        # this must be an arithmetic operation on our struc ptr, we must type the immediate value
        # this assumes the src reg is before the immediate, which is the case on IDA disass for arm and x64
        if (
            op.type == idaapi.o_imm
            and op.n > 0
            and insn.ops[op.n - 1].type == idaapi.o_reg
            and insn.ops[op.n - 1].reg == regid
        ):
            imm_size = idaapi.get_dtype_size(op.dtype)

            displ = op.value
            shift = utils.to_c_integer(off - displ, imm_size)

            return (op, shift)

    return (None, 0)


# type operand with the given "struct offset"
def apply_stroff_to_op(ea: int, regid: int, struc: idaapi.tinfo_t, off: int):
    insn = idaapi.insn_t()
    if idaapi.decode_insn(insn, ea) == 0:
        return

    udm = idaapi.udm_t()
    udm.offset = off * 8
    mid = struc.get_udm_tid(ida_utils.find_udm_wrap(struc, udm))
    path = idaapi.tid_array(idaapi.MAXSTRUCPATH)

    op, shift = find_op_for_stroff(insn, regid, off)
    if op is None:
        utils.g_logger.warning(f"No op to apply stroff for {ea:#x} {idaapi.get_reg_name(regid,8)}({regid:#x})")
        return

    # type operand with struc path
    path[0] = struc.get_tid()
    path[1] = mid
    idaapi.op_stroff(ea, op.n, path.cast(), 2, shift)

    idaapi.auto_wait()  # let IDA digest

    # IDA 8.4: in some cases op_stroff does not set the right struc path
    # instead of '[#struc.field_0]' we end up with '[#struc]'
    # thus missing an xref on field_0 for the instruction
    # this "fix" should force the xref
    if mid not in idautils.DataRefsFrom(ea):
        path[0] = mid
        idaapi.op_stroff(ea, op.n, path.cast(), 1, shift)  # type op
        idaapi.add_dref(ea, mid, idaapi.dr_I | idaapi.XREF_USER)  # force xref

    utils.g_logger.debug(f"Typing op {ea:#x} {op.n} with stroff {path[0]:#x}:{shift:#x}")


# type IDA base with data from given entrypoint
def type_entry(entry: entrypoints.entry_t, ctx: entrypoints.context_t):
    if not should_type_entry(entry, ctx):
        utils.g_logger.debug(f"Not typing database with {entry.entry_id()} data")
        return

    # make sure the associated structure exists in IDA
    shift, struc = entry.get_structure()
    if struc.ida_tid == idaapi.BADADDR:
        utils.g_logger.warning(
            f'Structure "{struc.get_name()}" was not generated, preventing from typing {entry.entry_id()}'
        )
        return

    struc_tif = struc.find_tinfo()

    utils.g_logger.debug(f"Typing database with {entry.entry_id()} data")

    # type disassembly operands
    for ea, regid, offs in entry.get_operands():
        apply_stroff_to_op(ea, regid, struc_tif, shift + offs[0])

        # multiple fields referenced by one instruction, add xrefs on additional fields
        for i in range(1, len(offs)):
            udm = idaapi.udm_t()
            udm.offset = (shift + offs[i]) * 8
            mid = struc_tif.get_udm_tid(ida_utils.find_udm_wrap(struc_tif, udm))
            idaapi.add_dref(ea, mid, idaapi.dr_I | idaapi.XREF_USER)
            utils.g_logger.debug(f"Adding xref for field {struc_tif.get_tid():#x}:{(shift + offs[i]):#x} on {ea:#x}")

    # type containing function
    fct_ea = entry.get_function()
    if fct_ea != idaapi.BADADDR:
        fct = ctx.get_function(fct_ea)

        # type function's arguments
        type_function_argument(fct, entry)

        # type function's return
        type_function_return(fct, entry)


# set type & rename memory allocators if needed
def type_allocator(alloc: allocators.allocator_t):
    # give a default name
    if not symbols.has_relevant_name(alloc.ea):
        idaapi.set_name(alloc.ea, alloc.get_name())

    # set function type
    func_tinfo, func_data = ida_utils.get_or_create_fct_type(alloc.ea)
    if func_tinfo.is_ptr():  # avoid function pointers
        return

    alloc.make_type(func_data)

    if func_tinfo.create_func(func_data):
        idaapi.apply_tinfo(alloc.ea, func_tinfo, idaapi.TINFO_DEFINITE)

        utils.g_logger.info(f"Typing allocator_{alloc.ea:x} ({alloc.get_name()})")


# apply __cppobj & VFT flags
def apply_udt_flags(struc: structure_t, tinfo: idaapi.tinfo_t):
    taudt = idaapi.TAUDT_CPPOBJ if struc.is_cppobj() else 0
    taudt |= idaapi.TAUDT_VFTABLE if struc.is_vtable() else 0
    if taudt == 0:
        return

    # apply flags to tinfo
    details = idaapi.udt_type_data_t()
    tinfo.get_udt_details(details)
    details.taudt_bits |= taudt
    tinfo.create_udt(details)


# add given field to given IDA structure
def add_field_to_IDA_struc(struc: idaapi.tinfo_t, field: field_t, updated: Dict[int, Tuple[idaapi.tinfo_t, int]]):
    bits_offset = field.offset * 8
    bits_size = field.size * 8

    t_ord = struc.get_ordinal()
    if t_ord == 0:  # ordinal number was lost
        pass

    elif t_ord not in updated:
        updated[t_ord] = (struc.copy(), struc.get_size())  # copy or pray
        existing.remove_padd_fields(struc)  # reset gapX fields as padding
    else:
        struc, _ = updated[t_ord]  # use our updated tinfo, not IDA's

    # search for existing field
    udm = idaapi.udm_t()
    udm.offset = bits_offset
    if ida_utils.find_udm_wrap(struc, udm) == idaapi.BADADDR:
        pass

    elif udm.is_gap():  # no STRMEM_SKIP_GAPS on IDA 8
        # we want to add a field beyond the gap, without knowing what's after - abort
        # a gap should not be followed by another gap
        if bits_offset + bits_size > udm.offset + udm.size:
            utils.g_logger.warning(
                f"Abort making {field} into {struc.get_type_name()}: bigger than gap[{udm.offset//8:#x}:{udm.size//8:x}]"
            )
            return

        udm = idaapi.udm_t()  # ignore gap

    # field is within an embedded structure
    elif udm.type.is_udt() and (udm.offset + udm.size) >= (bits_offset + bits_size):
        field.offset = (bits_offset - udm.offset) // 8  # update field_t directly, it is not re-used after
        return add_field_to_IDA_struc(udm.type, field, updated)

    # existing field with different boundaries
    elif udm.offset != bits_offset or udm.size != bits_size:
        utils.g_logger.warning(
            f"Abort making {field} into {struc.get_type_name()}: conflict with {udm.name}[{udm.offset//8:#x}:{udm.size//8:x}]"
        )
        return

    # replace field type if ok to do so
    ftif = field.get_type()
    if udm.type.get_realtype() == idaapi.BT_UNK or (
        existing.should_field_type_be_replaced(udm.type) and not existing.should_field_type_be_replaced(ftif)
    ):
        udm.type = ftif

    # set field comment if no existing
    fcomm = field.get_comment()
    if fcomm and len(udm.cmt) == 0:
        udm.cmt = fcomm

    # replace field name if needed
    fname = field.get_name()
    if existing.should_field_name_be_replaced(field.offset, udm.name, fname):
        udm.name = fname

    # add field to struc tinfo
    udm.offset = bits_offset
    udm.size = bits_size
    tcode = struc.add_udm(udm, idaapi.ETF_MAY_DESTROY)
    if tcode != idaapi.TERR_OK:
        utils.g_logger.error(
            f'Failed making {udm.name} (off {udm.offset//8:#x}, size {udm.size//8:#x}, type "{udm.type}") to {struc.get_type_name()}: "{idaapi.tinfo_errstr(tcode)}" ({tcode:#x})'
        )


# fill IDA structure with given model info
# does not overwrite fields of already existing IDA structure
def fill_IDA_structure(struc: structure_t):
    if struc.ida_tid == idaapi.BADADDR:
        utils.g_logger.error(f'Could not generate structure "{struc.get_name()}"')
        return

    struc_tif = struc.find_tinfo()

    # record of structures to update (current struc and its embedded strucs)
    updated: Dict[int, Tuple[idaapi.tinfo_t, int]] = dict()
    updated[struc_tif.get_ordinal()] = (struc_tif, struc_tif.get_size())
    existing.remove_padd_fields(struc_tif)

    # set udt attr
    apply_udt_flags(struc, struc_tif)

    # add fields
    for field in struc.fields.values():
        add_field_to_IDA_struc(struc_tif, field, updated)

    # set structure's comment
    scomm = struc.get_comment()
    if scomm and struc_tif.get_type_cmt() is None:
        tcode = struc_tif.set_type_cmt(scomm)
        if tcode != idaapi.TERR_OK:
            utils.g_logger.error(
                f'Failed to set comment for {struc.get_name()}: "{idaapi.tinfo_errstr(tcode)}" ({tcode:#x})'
            )

    # reset gapX fields on all updated structures + save to IDA
    while len(updated):
        t_ord, (tinfo, min_size) = updated.popitem()
        existing.add_padd_fields(tinfo, min_size)
        tinfo.set_numbered_type(None, t_ord, idaapi.NTF_REPLACE)


# imports all structures defined into given record into IDA
def import_structures(record: structure_record_t):
    # prepare symless structures directory
    make_structures_dir()

    # create empty structures
    for struc in record.get_structures(include_discarded=False):
        make_IDA_structure(struc)

    # fill the structures
    for struc in record.get_structures(include_discarded=False):
        fill_IDA_structure(struc)

    # type vtables with vtables structures
    for vtbl in record.get_structures(cls=vtable_struc_t, include_discarded=False):
        tinfo = vtbl.find_tinfo()
        if not idaapi.apply_tinfo(vtbl.ea, tinfo, idaapi.TINFO_DEFINITE):
            utils.g_logger.warning(f"Could not apply type {tinfo} to vtable 0x{vtbl.ea:x}")


# apply structures types to IDA base
def import_context(context: entrypoints.context_t):
    entries = context.get_entrypoints()

    # type entries
    for entry in entries.get_entries():
        type_entry(entry, context)

    # type allocators
    for allocator in context.get_allocators():
        type_allocator(allocator)
