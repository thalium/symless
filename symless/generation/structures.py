from collections import defaultdict
from typing import Dict, List, Tuple

import symless.conflict as conflict
import symless.model.entrypoints as entrypoints
import symless.symbols.rename as rename
import symless.utils.utils as utils
from symless.generation import *


# create a structure's field (fixed) from an entrypoint's field (ambiguous)
# size_solver_cb is used to choose prefered field's size
def make_field(
    var_field: model.field_t, shift: int, flow: model.entry_t, block: model.block_t, size_solver_cb
) -> "field_t":
    var_type = var_field.get_type()
    offset = shift + var_field.offset

    # unknown pointer
    if isinstance(var_type, model.ftype_ptr_t):
        v = var_type.value.get_uval()  # value size is assumed to be ptr_size
        return ptr_field_t(v, offset, flow, block)

    # structure pointer
    if isinstance(var_type, model.ftype_struc_t):
        # vtable pointer
        if isinstance(var_type.entry, model.vtbl_entry_t):
            return vtbl_ptr_field_t(list(var_field.type), offset, flow, block)

        else:
            return struc_ptr_field_t(var_type.entry, offset, flow, block)

    # function pointer
    if isinstance(var_type, model.ftype_fct_t):
        fea = var_type.value.get_uval()
        return fct_ptr_field_t(fea, offset, flow, block)

    size = size_solver_cb(var_field)
    return field_t(offset, size, flow, block)


# fill structures models
def define_structure(struc: structure_t):
    visited: Set[Tuple[model.entry_t, model.block_t, int]] = set()

    # get structures fields from associated entries fields
    for root, node, shift in struc.node_flow():
        # do not visit the same node twice, with the same shift
        path_id = (node.get_owner(), node, shift)
        if path_id in visited:
            continue
        visited.add(path_id)

        # add all fields from node
        for vfield in node.get_fields():
            # structure field from entrypoint field
            field = make_field(vfield, shift, root, node, conflict.field_size_solver)
            struc.set_field(field, conflict.fields_conflicts_solver)

    # search for xrefs on paddings and create dummy fields for it
    # this happens when the address of a field is used, without its content beeing accessed
    for entry, node, shift in visited:
        for _, _, offs in entry.get_operands():
            for off in offs:
                eoff = shift + off
                if struc.has_field_at(eoff) is None and eoff < struc.get_size():
                    struc.set_field(unk_data_field_t(eoff, node), None)


# define which structure an entry is associated to
def associate_entry(
    entry: entrypoints.entry_t, entries: entrypoints.entry_record_t
) -> Optional[Tuple[int, structure_t]]:
    if not entry.has_structure():
        # read entries special case
        if isinstance(entry, model.read_entry_t):
            # get the read field
            src_shift, src_struc = associate_entry(entry.src, entries)
            field = src_struc.get_field(entry.src_off + src_shift)
            if not isinstance(field, struc_ptr_field_t):
                entries.remove_entry(entry)
                return None

            eff_shift, eff_struc = associate_entry(field.value, entries)
            utils.g_logger.debug(
                f"{entry.entry_id()} associated with struc {eff_struc.get_name()} (shift {eff_shift:#x})"
            )

            entry.set_structure(eff_shift, eff_struc)

        else:
            # select less derived structure that flew through this ep
            candidates: List[Tuple[structure_t, int] | None] = list()
            for shift, parent in entry.get_parents():
                pshift, pstruc = associate_entry(parent, entries)
                candidates.append((pstruc, shift + pshift))

            selected = conflict.less_derived(candidates)
            entry.set_structure(selected[1], selected[0])

    return entry.get_structure()


# find best structure to associate to each entrypoint
def associate_entries(entries: model.entry_record_t):
    for entry in entries.get_entries():
        associate_entry(entry, entries)


# compute the owner of each defined vtable
def select_vtables_owners(record: structure_record_t):
    owners: Dict[vtable_struc_t, List[Tuple[structure_t, int]]] = defaultdict(list)

    # find all conflicts on owners
    for struc in record.get_structures(include_discarded=False):
        for field in struc.fields.values():
            if not isinstance(field, vtbl_ptr_field_t):
                continue

            _, vtbl = field.get_structure()
            owners[vtbl].append((struc, field.offset))

    # select owner among candidates for each vtable
    for vtbl in owners:
        owner, shift = conflict.vtable_owner_solver(owners[vtbl])
        vtbl.set_class(owner, shift)


# generate structures models from entrypoints
def define_structures(ctx: entrypoints.context_t) -> structure_record_t:
    entries = ctx.get_entrypoints()
    record = structure_record_t(entries)

    # make strucs models and generate empty structures
    for struc in record.get_structures():
        define_structure(struc)

    # define which structure to be associated to each entry
    associate_entries(entries)

    # find & merge duplicated structures
    conflict.remove_dupes(entries, record)

    # associate vtables to their owners
    select_vtables_owners(record)

    # rename structure models using symbols
    rename.define_structures_names(record)

    return record
