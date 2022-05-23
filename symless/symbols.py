import re
from typing import Tuple

import idaapi

import symless.conflict as conflict
import symless.cpustate.arch as arch
import symless.ida_utils as ida_utils
import symless.model as model
import symless.utils.utils as utils

re_struc_name_invalids = re.compile(r"[\s\*&]")
re_struc_name_invalids2 = re.compile(r"[,\-+]")
re_struc_name_invalids3 = re.compile(r"[<>]")

re_ctors = re.compile(r"\b((?:[\w_]+::)*)([\S ]+)::\2(?:\(|$)")

re_vtable_single_msvc = re.compile(r"^const (.+)::`vftable'$")
re_vtable_single_gcc = re.compile(r"^`vtable for'([\s\S]+)$")
re_tinfo_gcc = re.compile(r"^`typeinfo for'([\s\S]+)$")
re_vtable_for_msvc = re.compile(r"^const (.+)::`vftable'{for `(.+)'}")


# ea was given a (non-dummy) name
def has_name(ea: int):
    flags = idaapi.get_flags(ea)
    return idaapi.has_any_name(flags) and not idaapi.has_dummy_name(flags)


# Remove unvalid char for setType() in struc name
def struc_name_cleanup(original: str) -> str:
    out = re_struc_name_invalids.sub("", original)
    out = re_struc_name_invalids2.sub("_", out)
    out = re_struc_name_invalids3.sub("__", out)
    return out


# simplified method name from full signature
def get_method_name_from_signature(signature: str) -> str:
    signature = signature.split("(")[0]

    if "::" in signature:
        signature = signature.split("::")[-1]
        methodName = signature.replace(" ", "_")
        methodName = re.sub("[^0-9a-zA-Z_]", "", methodName)
        methodName = re.sub("_+", "_", methodName).strip("_")
    else:
        methodName = signature.split(" ")[-1]

    return methodName


# get (class, parent_class) from vtable label
def get_classnames_from_vtable(vtable_ea: int) -> Tuple[str, str]:
    if arch.is_elf():
        return get_classnames_from_vtable_gcc(vtable_ea)
    return get_classnames_from_vtable_msvc(vtable_ea)


def get_classnames_from_vtable_gcc(vtable_ea: int) -> Tuple[str, str]:
    ptr_size = ida_utils.get_ptr_size()

    # use vtable symbol
    label_ea = vtable_ea - (2 * ptr_size)
    vtbl_name = ida_utils.demangle(idaapi.get_name(label_ea))

    m = re_vtable_single_gcc.search(vtbl_name)
    if m is not None:
        return (struc_name_cleanup(m.group(1)), None)

    # fallback - use typeinfo symbol
    tinfo_ea = ida_utils.__dereference_pointer(vtable_ea - ptr_size, ptr_size)
    tinfo = ida_utils.demangle(idaapi.get_name(tinfo_ea))

    m = re_tinfo_gcc.search(tinfo)
    if m is not None:
        return (struc_name_cleanup(m.group(1)), None)

    return (None, None)


def get_classnames_from_vtable_msvc(vtable_ea: int) -> Tuple[str, str]:
    vtbl_name = ida_utils.demangle(idaapi.get_name(vtable_ea))

    if vtbl_name is None or "::" not in vtbl_name:
        return (None, None)

    m = re_vtable_single_msvc.search(vtbl_name)
    if m is not None:
        return (struc_name_cleanup(m.group(1)), None)

    m = re_vtable_for_msvc.search(vtbl_name)
    if m is not None:
        return (struc_name_cleanup(m.group(1)), struc_name_cleanup(m.group(2)))

    return (None, None)


# get method class from its name
def get_classname_from_ctor(fct_name: str) -> str:
    if fct_name is None or "::" not in fct_name:
        return None

    m = re_ctors.search(fct_name)
    if m is None:
        return None

    return m.group(1) + m.group(2)


# does given methods belong to given class
def is_method_from_class(fea: int, classname: str) -> bool:
    name = ida_utils.demangle(idaapi.get_name(fea))
    if name is None:
        return False

    return name.startswith(f"{classname}::")


# use ctors symbols to name structures
def recover_names_from_ctors(ctx: model.context_t, names: set) -> set:
    for function in ctx.functions.values():

        # function is a ctor
        objname = get_classname_from_ctor(ida_utils.demangle(idaapi.get_name(function.ea)))
        if objname is None or function.args_count == 0 or function.selected_args[0] is None:
            continue

        # function takes a non-shifted first param
        model, shift = function.selected_args[0]
        if model.has_name() or shift != 0 or model.is_vtable():
            continue

        # first function to propagate the model on was of given class
        if model.ctor_ea is None or not is_method_from_class(model.ctor_ea, objname):
            continue

        objname = struc_name_cleanup(objname)
        if objname not in names:  # or else we got a ctor wrong
            model.set_name(objname)
            names.add(objname)

    return names


# use vtables labels to name structures
def recover_names_from_vtables(ctx: model.context_t) -> set:
    names_cflt = dict()  # name -> set of models

    # Get name for each struct
    for mod in ctx.get_models():

        if mod.has_name():
            continue

        if mod.is_vtable():
            derived, parent = get_classnames_from_vtable(mod.get_ea())
            if derived is None:
                continue

            if parent is not None:
                base = f"{derived}_{parent}"
            else:
                base = f"{derived}"

            name = f"{base}{idaapi.VTBL_SUFFIX}"

            # no conflict on vtable name
            if name in names_cflt:
                name = f"{base}_{mod.get_ea():x}{idaapi.VTBL_SUFFIX}"

        else:
            vtbl_sid = mod.get_vtable(0)
            if vtbl_sid < 0:
                continue

            vtable = ctx.models[vtbl_sid]
            name, _ = get_classnames_from_vtable(vtable.get_ea())

            if name is None:
                continue

        if name not in names_cflt:
            names_cflt[name] = set()
        names_cflt[name].add(mod)

    # solve conflicts
    for name in names_cflt:
        selected = conflict.find_less_derived([(i, 0) for i in names_cflt[name]])
        selected[0].set_name(name)

    return set(names_cflt.keys())


# use symbols to name vtable members
def recover_virtual_functions_names(ctx: model.context_t):
    ptr_size = ida_utils.get_ptr_size()
    for mod in ctx.get_models():
        if not mod.is_vtable():
            continue

        i = 0
        presents = set()
        for fea in ida_utils.vtable_members(mod.get_ea()):
            if has_name(fea):
                name = get_method_name_from_signature(ida_utils.demangle(idaapi.get_name(fea)))
                if name not in presents:
                    mod.members_names[i] = name
                    presents.add(name)
                else:
                    mod.members_names[i] = f"{name}_{(i * ptr_size):x}"
            i += 1


# recover name from ctor_ea for all unamed objects
def last_chance_name_recovery(ctx: model.context_t, names: set):
    for mod in ctx.get_models():

        if mod.has_name():
            continue

        utils.logging.debug(f"{mod} {mod.has_name()} {[hex(x) for x in mod.ea]}")

        # Rename the struc with the name of the first func containing its allocator
        # Far from being perferct but does the trick sometimes and is not worse than nothing in other cases
        if mod.ctor_ea is not None:
            objname = get_classname_from_ctor(ida_utils.demangle(idaapi.get_name(mod.ctor_ea)))
            if objname is not None and objname not in names:
                mod.set_name(objname)
                names.add(objname)
                continue

        if mod.ctor_ea is None:
            func = idaapi.get_func(mod.ea[0])
            if func is None:
                continue
            objname = get_method_name_from_signature(
                ida_utils.demangle(idaapi.get_func_name(func.start_ea))
            )
            if objname is None or objname.startswith("sub_"):
                continue
            nbStrucSameName = 1
            original_objname = objname
            while objname in names:
                objname = "%s%d" % (original_objname, nbStrucSameName)
                nbStrucSameName += 1
            mod.set_name("struc_" + objname)
            names.add(objname)
            continue


def name_struc_members(ctx: model.context_t):
    for mod in ctx.get_models():
        members_names = mod.get_guessed_names()
        for i in range(len(members_names)):
            elt = members_names[i]
            members_names[i] = (
                elt[0],
                get_method_name_from_signature(ida_utils.demangle(elt[1])),
            )


# name structures using symbols
def name_structures(ctx: model.context_t):
    names = recover_names_from_vtables(ctx)
    recover_names_from_ctors(ctx, names)
    last_chance_name_recovery(ctx, names)
    recover_virtual_functions_names(ctx)
    name_struc_members(ctx)
