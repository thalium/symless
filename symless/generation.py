from typing import Dict, Tuple

import ida_dirtree
import idaapi
import idc

import symless.cpustate.cpustate as cpustate
import symless.existing as existing
import symless.ida_utils as ida_utils
import symless.model as model
import symless.symbols as symbols
import symless.utils as utils

STRUC_DIR: ida_dirtree.dirtree_t
STRUC_DIR = None

# Apply struc type on operand
def set_operand_type(ea: int, n: int, sid: int, shift: int):
    path = idaapi.tid_array(1)
    path[0] = sid
    idaapi.op_stroff(ea, n, path.cast(), 1, shift)


# get flags giving the right type for given struct member size
def get_data_flags(size: int):
    flags = idaapi.FF_DATA
    if size < 32:  # avoid ymmword type, raises warnings
        flags |= idaapi.get_flags_by_size(size)
    return flags


# Add padding fields into struct
def padd_struc(struc: idaapi.struc_t, size: int):
    current, next = 0, 0
    struc_size = idaapi.get_struc_size(struc.id)

    while next != struc_size:
        if idc.get_member_id(struc.id, next) != -1:
            if next - current > 0:
                msize = next - current
                idaapi.add_struc_member(
                    struc, f"padd__{current:08x}", current, get_data_flags(msize), None, msize
                )
            next = idc.get_next_offset(struc.id, next)
            current = next
        else:
            next = idc.get_next_offset(struc.id, next)

    if struc_size < size:
        msize = size - struc_size
        idaapi.add_struc_member(
            struc, f"padd__{struc_size:08x}", struc_size, get_data_flags(msize), None, msize
        )


def get_model_tinfo(m: model.model_t) -> idaapi.tinfo_t:
    return ida_utils.get_local_type(m.get_name())


def get_model_ptr_tinfo(m: model.model_t) -> idaapi.tinfo_t:
    tinfo = get_model_tinfo(m)
    tinfo.create_ptr(tinfo)
    return tinfo


# Generate a new struc implementing given model
def generate_struct(model: model.model_t, ctx: model.context_t) -> int:
    utils.logger.debug(f"generating content of struct {model.get_name()}")
    sid = idaapi.get_struc_id(model.get_name())

    if sid == idaapi.BADADDR:
        utils.logger.critical(f"Problem struc {model.get_name()} was not created")
        return

    struc = idaapi.get_struc(sid)

    # make space
    existing.remove_padd_fields(struc)

    # add members
    for (offset, size) in model.members:
        utils.logger.debug(f"add struc member {(offset, size)}")
        idaapi.add_struc_member(
            struc, f"field_{offset:08x}", offset, get_data_flags(size), None, size
        )

    # set struct comment
    if not has_struc_comment(sid):
        set_struc_comment(model, sid)

    # make padding fields
    padd_struc(struc, model.size)

    if model.is_vtable():
        # name & type vtable content
        populate_vtable(model, struc)

        # apply vtable type to vtable ea
        idaapi.apply_tinfo(model.get_ea(), get_model_tinfo(model), idaapi.TINFO_DEFINITE)
    else:
        # vtable ptrs typing
        type_vtable_ptrs(model, struc, ctx)

        # mark vtable ptrs
        mark_vtable_ptrs(model)

        set_guessed_name_members(model, struc, ctx)

    # TODO possible upgrade: if stroff exists, replace by struc returned by less_derived(current, existing)

    # apply struc offsets on operands
    for (ea, n, shift) in model.get_operands():
        utils.logger.debug(f"creating crefs ea:{hex(ea)} n : {n} shift : {shift}")
        if not existing.has_op_stroff(ea, n):
            set_operand_type(ea, n, sid, shift)

    return sid


# set structure comment
def set_struc_comment(model: model.model_t, sid: int):
    if model.is_struct():
        idaapi.set_struc_cmt(sid, "Allocated at: %s" % ", ".join(map(hex, model.ea)), False)
    elif model.is_varsize_struct():
        if len(model.ea) > 0:
            idaapi.set_struc_cmt(
                sid,
                "Not directly allocated, ctors/dtors: %s" % ", ".join(map(hex, model.ea)),
                False,
            )
    elif model.selected_owner is not None:
        idaapi.set_struc_cmt(
            sid,
            "Vtable at: %s of %s"
            % (", ".join(map(hex, model.ea)), model.selected_owner[0].get_name()),
            False,
        )


def has_struc_comment(sid: int) -> bool:
    return idaapi.get_struc_cmt(sid, False) is not None


# set
def set_guessed_name_members(model: model.model_t, struc: idaapi.struc_t, ctx: model.context_t):

    for (offset, name) in model.get_guessed_names():
        idaapi.set_member_name(struc, offset, name)


# set type & name of struc vtable ptrs
def type_vtable_ptrs(model: model.model_t, struc: idaapi.struc_t, ctx: model.context_t):
    first = True
    for (offset, vtable_sid) in model.get_vtables():
        member = idaapi.get_member(struc, offset)

        vtable = ctx.models[vtable_sid]
        generate_struct(vtable, ctx)

        if first:
            name = idaapi.VTBL_MEMNAME
            first = False
        else:
            name = f"{idaapi.VTBL_MEMNAME}_{offset:08x}"

        idaapi.set_member_name(struc, offset, name)

        idaapi.set_member_tinfo(struc, member, 0, get_model_ptr_tinfo(vtable), 0)

        idaapi.set_member_cmt(member, vtable.get_name(), False)


# mark vtable ptrs of given model with TAFLD_VFTABLE flag
# removes vtable indirection on virtual method call, but move the struct to the local types
def mark_vtable_ptrs(model: model.model_t):
    if len(model.vtables) <= 1:  # not necessary when only 1 vtable
        return

    tinfo = get_model_tinfo(model)

    data = idaapi.udt_type_data_t()
    if not tinfo.get_udt_details(data):
        return

    data.taudt_bits |= idaapi.TAUDT_CPPOBJ  # set __cppobj flag on the struct

    for member in data:
        offset = int(member.offset / 8)
        if model.get_vtable(offset) != -1:
            member.set_vftable()

    tinfo.create_udt(data, idaapi.BTF_STRUCT)
    tinfo.set_named_type(idaapi.get_idati(), model.get_name(), idaapi.NTF_REPLACE)


# Set up vtable members name & types
def populate_vtable(vtable: model.model_t, struc: idaapi.struc_t):
    i = 0
    for fea in ida_utils.vtable_members(vtable.get_ea()):
        offset = vtable.members[i][0]
        member = idaapi.get_member(struc, offset)

        # do not touch if member is already typed
        if not idaapi.get_member_name(member.id).startswith("field_"):
            i += 1
            continue

        # name
        idaapi.set_member_name(struc, offset, vtable.members_names[i])

        # comment
        idaapi.set_member_cmt(member, idaapi.get_name(fea), True)

        # type
        func_tinfo, func_data = get_or_create_fct_type(fea, idaapi.CM_CC_INVALID)
        func_data.cc = cpustate.get_abi().get_object_cc().cc  # force object cc

        if vtable.selected_owner is not None:
            owner, offset = vtable.selected_owner
            ida_utils.set_function_argument(
                func_data, 0, get_model_ptr_tinfo(owner), offset, get_model_tinfo(owner)
            )

        func_tinfo.create_func(func_data)
        func_tinfo.create_ptr(func_tinfo)

        idaapi.set_member_tinfo(struc, member, 0, func_tinfo, 0)

        i += 1


# Set type & rename memory allocators if needed
def set_allocators_type(allocators: list):
    for alloc in allocators:
        utils.logger.debug(f"allocator {alloc}")
        # set name
        if not symbols.has_name(alloc.ea):
            idaapi.set_name(alloc.ea, alloc.get_name())

        # set type
        cc = cpustate.get_abi().get_default_cc().cc
        func_tinfo, func_data = get_or_create_fct_type(alloc.ea, cc)
        alloc.make_type(func_data)

        if func_tinfo.create_func(func_data):
            idaapi.apply_tinfo(alloc.ea, func_tinfo, idaapi.TINFO_DEFINITE)


# get function type, create default one if none
def get_or_create_fct_type(
    fea: int, default_cc: int
) -> Tuple[idaapi.tinfo_t, idaapi.func_type_data_t]:
    func_tinfo = idaapi.tinfo_t()
    func_data = idaapi.func_type_data_t()

    if idaapi.get_tinfo(func_tinfo, fea):
        # unable to retrieve func_data on __high fcts, maybe try get_func_details(func_data, GTD_NO_ARGLOCS) ?
        if not func_tinfo.get_func_details(func_data):
            return (idaapi.tinfo_t(), ida_utils.new_func_data(default_cc))
    else:
        # call decompiler to get more info
        try:
            import ida_hexrays

            cfunc = ida_hexrays.decompile_func(
                idaapi.get_func(fea), ida_hexrays.hexrays_failure_t(), 0
            )
            if cfunc.__deref__() is not None and cfunc.get_func_type(func_tinfo):
                func_tinfo.get_func_details(func_data)
                return (func_tinfo, func_data)

        except ImportError:
            pass

        func_data = ida_utils.new_func_data(default_cc)

    return (func_tinfo, func_data)


# type functions crossed during state propagation
def set_functions_type(functions: Dict[int, model.function_t], force: bool = True):
    for function in functions.values():
        utils.logger.debug(f"typing function {function}")
        if not function.has_selected_args():
            continue

        cc = idaapi.CM_CC_UNKNOWN if function.cc is None else function.cc.cc
        func_tinfo, func_data = get_or_create_fct_type(function.ea, cc)

        # set ret type
        if function.selected_ret is not None and (
            force or existing.can_type_be_replaced(func_data.rettype)
        ):
            model, shift = function.selected_ret

            ret_type = get_model_ptr_tinfo(model)
            ida_utils.shift_ptr(ret_type, get_model_tinfo(model), shift)
            func_data.rettype = ret_type

        # set args types
        for (index, model, shift) in function.get_selected_args():

            # check that we can replace existing arg
            if (
                not force
                and index < func_data.size()
                and not existing.can_type_be_replaced(func_data[index].type)
            ):
                continue

            ida_utils.set_function_argument(
                func_data, index, get_model_ptr_tinfo(model), shift, get_model_tinfo(model)
            )

        if func_tinfo.create_func(func_data):
            idaapi.apply_tinfo(function.ea, func_tinfo, idaapi.TINFO_DEFINITE)


def move_struc_to_symless_dir(name):
    global STRUC_DIR
    if STRUC_DIR is None:
        STRUC_DIR = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_STRUCTS)
    STRUC_DIR.rename(name, "symless/" + name)


# Generate structures from model
def generate_structs(ctx: model.context_t) -> int:

    utils.logger.info(
        "Generating %d structures.." % sum([(0 if i.is_empty() else 1) for i in ctx.get_models()])
    )

    # generate empty strucs to be used as types
    for mod in ctx.get_models():
        if not mod.is_empty() and idaapi.get_struc_id(mod.get_name()) == idaapi.BADADDR:
            utils.logger.debug(f"Generating empty {mod.get_name()}")
            sid = idaapi.add_struc(idaapi.BADADDR, mod.get_name(), False)
            if sid == idaapi.BADADDR:
                mod.set_name(None)  # struct was not added because of bad name
                sid = idaapi.add_struc(idaapi.BADADDR, mod.get_name(), False)
            if sid == idaapi.BADADDR:
                utils.logger.warning(f"Problem generating {mod.get_name()} structure")
            else:
                mod.sid_ida = sid
                move_struc_to_symless_dir(mod.get_name())

    # type functions
    set_allocators_type(ctx.allocators)
    set_functions_type(ctx.functions)

    # populate structures
    total = 0
    for mod in ctx.get_models():
        if mod.is_empty():
            continue

        generate_struct(mod, ctx)
        total += 1

    return total
