import idaapi

import symless.ida_utils as ida_utils
import symless.model as model

''' From existing structure back to model '''


# convert an existing struct to a model
def from_structure(struc: idaapi.struc_t, ea: int = None) -> (model.model_t, model.context_t):
    out = model.model_t(-1, ea, type = model.model_type.STRUCTURE_UKWN_SIZE)
    out.set_name(idaapi.get_struc_name(struc.id))

    context = model.context_t()
    context.add_model(out)

    for member in struc.members:
        name = idaapi.get_member_name(member.id)

        if not name.startswith("padd_"): # ignore padding fields
            out.add_member(member.soff, idaapi.get_member_size(member))

            # check for vtable ptr
            tinfo = idaapi.tinfo_t()
            ptr_details = idaapi.ptr_type_data_t()
            if idaapi.get_member_tinfo(tinfo, member) and tinfo.get_ptr_details(ptr_details):

                vtbl_struc = ida_utils.struc_from_tinfo(ptr_details.obj_type)
                if vtbl_struc is not None:
                    v_ea, v_name = ida_utils.get_vtable_ea(vtbl_struc)
                    if v_ea != idaapi.BADADDR:
                        vtable = context.get_or_create_vtable(v_ea, idaapi.get_struc_size(vtbl_struc))
                        out.add_vtable(member.soff, vtable.sid)

    return (out, context)


# set existing structure padding fields to undefined
def remove_padd_fields(struc: idaapi.struc_t):
    offset = idaapi.get_struc_first_offset(struc)
    size = idaapi.get_struc_size(struc)

    while offset < size and offset != idaapi.BADADDR:
        member = idaapi.get_member(struc, offset)

        if member is not None: # avoid undefined fields
            name = idaapi.get_member_name(member.id)
            if name.startswith("padd_"):
                idaapi.del_struc_member(struc, offset)

        offset = idaapi.get_struc_next_offset(struc, offset)


# was a struct path applied on operand
def has_op_stroff(ea: int, n: int):
    delta, path = idaapi.sval_pointer(), idaapi.tid_array(idaapi.MAXSTRUCPATH)
    return idaapi.get_stroff_path(path.cast(), delta.cast(), ea, n) > 0


# can we replace existing type with a struct type
# only if type is a scalar or a scalar ptr
def can_type_be_replaced(tinfo: idaapi.tinfo_t) -> bool:
    ptr_data = idaapi.ptr_type_data_t()
    if tinfo.get_ptr_details(ptr_data):
        tinfo = ptr_data.obj_type
    return tinfo.is_scalar() and not tinfo.is_enum()