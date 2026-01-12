from collections import deque
from typing import Collection, Tuple

import idaapi

import symless.generation as generation
import symless.utils.ida_utils as ida_utils
import symless.utils.utils as utils


# add special gap field to structure
def make_gap(struc: idaapi.tinfo_t, off: int, size: int):
    udm = idaapi.udm_t()
    udm.offset = off * 8
    udm.size = size * 8
    udm.name = f"gap{off:X}"
    udm.tafld_bits |= idaapi.TAFLD_GAP  # is_gap

    # set type to _BYTE[size]
    arr = idaapi.array_type_data_t(0, size)
    arr.elem_type = ida_utils.get_basic_type(idaapi.BT_VOID | idaapi.BTMT_SIZE12)
    udm.type = idaapi.tinfo_t()
    udm.type.create_array(arr)

    tcode = struc.add_udm(udm, idaapi.ETF_MAY_DESTROY)
    if tcode != idaapi.TERR_OK:
        utils.g_logger.error(
            f'Failed to gap {struc.get_type_name()} with {udm.name} (size {size:#x}, type "{udm.type}"): "{idaapi.tinfo_errstr(tcode)}" ({tcode:#x})'
        )


# remove padding fields from structure
def remove_padd_fields(struc: idaapi.tinfo_t):
    details = idaapi.udt_type_data_t()
    struc.get_udt_details(details)

    # search for gaps
    gaps: Collection[Tuple[int, int]] = deque()
    for udm in details:
        if udm.name == f"gap{(udm.offset // 8):X}":  # gap identified by name
            # we do not want consecutive gaps latter, merge them
            if len(gaps) and gaps[0][1] == udm.offset:
                gaps[0] = (gaps[0][0], udm.offset + udm.size)
            else:
                gaps.appendleft((udm.offset, udm.offset + udm.size))

    # merge all gaps into real gaps fields
    for off, end in gaps:
        make_gap(struc, off // 8, (end // 8) - (off // 8))


# remove gap flag from padd fields
# + padd to reach at least min_size bytes
def add_padd_fields(struc: idaapi.tinfo_t, min_size: int):
    csize = struc.get_size()
    if csize < min_size:  # padd to final size
        make_gap(struc, csize, min_size - csize)

    # remove gap flags from gaps - collapse padding
    details = idaapi.udt_type_data_t()
    struc.get_udt_details(details)
    for udm in details:
        udm.tafld_bits &= ~idaapi.TAFLD_GAP
    struc.create_udt(details)  # removes tid & ordinal info


# get the structure path assigned to given operand
def get_op_stroff(ea: int, n: int):
    delta, path = idaapi.sval_pointer(), idaapi.tid_array(idaapi.MAXSTRUCPATH)
    if idaapi.get_stroff_path(path.cast(), delta.cast(), ea, n) == 0:
        return idaapi.BADADDR
    return path[0]


# find existing vtable structure from vtable ea
def find_existing_vtable(ea: int) -> int:
    tinfo = idaapi.tinfo_t()
    if not (idaapi.get_tinfo(tinfo, ea) and tinfo.is_udt()):
        return idaapi.BADADDR
    return tinfo.get_tid()


# find existing structure with given name
def find_existing_structure(name: str) -> int:
    tinfo = ida_utils.get_local_type(name)
    if tinfo is None:
        return idaapi.BADADDR

    if tinfo.is_forward_struct():
        ida_utils.replace_forward_ref(tinfo)
    elif not tinfo.is_udt():
        return idaapi.BADADDR

    return tinfo.get_tid()


# should we replace an existing type in the idb by our struc ptr
# types we think it's ok to replace are void, scalars and scalars pointers
def should_arg_type_be_replaced(tinfo: idaapi.tinfo_t) -> bool:
    if tinfo.is_ptr():
        ptr_data = idaapi.ptr_type_data_t()
        if not tinfo.get_ptr_details(ptr_data) or ptr_data.parent.get_realtype() != idaapi.BT_UNK:
            return False
        tinfo = ptr_data.obj_type  # decide on pointee type

    # void, ints, floats, bools
    return idaapi.get_base_type(tinfo.get_realtype()) < idaapi.BT_PTR


# should we replace an existing struc field type
# only replace integers and void pointer
def should_field_type_be_replaced(tinfo: idaapi.tinfo_t) -> bool:
    if tinfo.is_ptr():
        ptr_data = idaapi.ptr_type_data_t()
        if not tinfo.get_ptr_details(ptr_data) or ptr_data.parent.get_realtype() != idaapi.BT_UNK:
            return False

        # void*
        return idaapi.get_base_type(ptr_data.obj_type.get_realtype()) == idaapi.BT_VOID

    # integers
    rt = idaapi.get_base_type(tinfo.get_realtype())
    return rt >= idaapi.BT_INT8 and rt <= idaapi.BT_INT


# should we rename a field, avoid renaming user-provided fields
def should_field_name_be_replaced(offset: int, old_name: str, new_name: str) -> bool:
    default_names = {  # record of preferred default names
        "": -1,
        generation.unk_data_field_t.get_default_name(offset): 0,
        generation.field_t.get_default_name(offset): 1,
        generation.ptr_field_t.get_default_name(offset): 2,
        generation.fct_ptr_field_t.get_default_name(offset): 3,
        generation.struc_ptr_field_t.get_default_name(offset): 3,
        generation.vtbl_ptr_field_t.get_default_name(offset): 4,
    }

    old_name_score = default_names.get(old_name, 5)
    new_name_score = default_names.get(new_name, 5)
    return new_name_score > old_name_score
