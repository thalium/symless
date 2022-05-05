import bisect
import collections
import math

import idaapi

import symless.cpustate.cpustate as cpustate
import symless.ida_utils as ida_utils
import symless.model as model

""" Within model conflicts resolution """

# between multiple structs containing a ptr to vtable,
# which one to use to type virtual functions
def select_vtable_owner(vtable: model.model_t):
    if len(vtable.owners) > 0:
        vtable.owners = find_less_derived(list(vtable.owners), vtable.get_ea())
    else:
        vtable.owners = None


""" Between models conflicts resolution """

# boundaries of a conflicting area
class boundary_t:
    def __init__(self, boundary):
        boundary = self.align_boundary(boundary)
        self.lower = boundary if boundary < 0 else 0
        self.upper = boundary if boundary > 0 else 0

    # 4 bytes alignement
    def align_boundary(self, boundary):
        babs = abs(boundary)
        sign = int(babs / boundary)
        return math.ceil(babs / 4) * 4 * sign

    def update_with(self, boundary):
        boundary = self.align_boundary(boundary)
        if boundary < self.lower:
            self.lower = boundary
        elif boundary > self.upper:
            self.upper = boundary

    def size(self) -> int:
        return self.upper - self.lower


# record of conflicting models
class belligerents_t:
    def __init__(self, candidates, vtable_conflict=False):
        self.key = tuple(candidates)  # tuple of (sid, offset)
        self.vtable_conflict = vtable_conflict

    def is_valid(self) -> bool:
        return len(self.key) > 1 and not self.vtable_conflict

    def get_subjects(self):
        for k in self.key:
            yield k  # (sid, offset)

    def dump(self, ctx: model.context_t):
        for sid, offset in self.get_subjects():
            model = ctx.models[sid]
            print("  for %s (%d) at %x" % (model.get_name(), model.sid, offset))

    def __eq__(self, other):
        if type(self) != type(other):
            return False

        return self.key == other.key

    def __hash__(self):
        return hash(self.key)


# records all conflicts
class conflicts_t:
    def __init__(self):
        self.conflicts = dict()  # belligerents_t -> boundary_t

    # build conflict key from all contestants
    def get_key(self, ea: int, n: int, candidates: set, ctx: model.context_t) -> belligerents_t:
        key = collections.deque()
        is_vtable_conflict = False
        for sid in candidates:
            candidate = ctx.models[sid]
            key.append((sid, candidate.get_shift_for_operand(ea, n)))
            is_vtable_conflict |= candidate.is_vtable()
        return belligerents_t(key, is_vtable_conflict)

    # add new conflicting area to the record
    def add_conflict(self, ea: int, n: int, boundary: int, candidates: set, ctx: model.context_t):
        key = self.get_key(ea, n, candidates, ctx)
        try:
            self.conflicts[key].update_with(boundary)
        except KeyError:
            self.conflicts[key] = boundary_t(boundary)

    def get_all_conficts(self):
        for bell in self.conflicts:
            if bell.is_valid():
                yield bell

    def get_conflicting_area(self, key: belligerents_t) -> boundary_t:
        return self.conflicts[key]

    def dump(self, ctx: model.context_t):
        for b in self.get_all_conficts():
            bound = self.get_conflicting_area(b)
            print(
                "Conflict on area [%x, %x] (size: %x):" % (bound.lower, bound.upper, bound.size())
            )
            b.dump(ctx)
            print()


""" Similar models merging """

# between two models, which one to keep and which one to merge
def who_to_merge(m1: model.model_t, m2: model.model_t):
    if m1.type == m2.type:
        if m1.sid < m2.sid:
            return (m1, m2)
        return (m2, m1)

    if m1.type < m2.type:
        return (m1, m2)

    return (m2, m1)


# is model built from given conflicting zone
def boundary_emcompass_model(model: model.model_t, shift: int, bound: boundary_t) -> bool:
    return (shift + bound.lower == 0) and (shift + bound.upper == model.size)


# get objects similar to subject in others set, using given conflicting area
def get_similar_models(ctx: model.context_t, bound: boundary_t, subject, others):
    out = [subject]
    model = ctx.models[subject[0]]

    if model.is_vtable():  # vtables are not duplicated
        return out

    for other in others:
        m_other = ctx.models[other[0]]
        if subject[1] == other[1] and model.is_similar(m_other):

            # Only merge unknown size models when conflict encompass them entirely
            if model.is_varsize_struct() and not boundary_emcompass_model(model, subject[1], bound):
                continue

            if m_other.is_varsize_struct() and not boundary_emcompass_model(
                m_other, other[1], bound
            ):
                continue

            bisect.insort_left(out, other)

    return out


# Identify and remove duplicated structures
def remove_duplicates(ctx: model.context_t, conflicts: conflicts_t):
    dupes = collections.deque()

    # identifiy duplicates
    for bell in conflicts.get_all_conficts():
        bound = conflicts.get_conflicting_area(bell)
        keys = set(bell.key)

        while len(keys) > 0:
            subject = keys.pop()
            similars = get_similar_models(ctx, bound, subject, keys)
            if len(similars) > 1:
                for i in similars:
                    try:
                        keys.remove(i)
                    except KeyError:
                        pass
                dupes.append(similars)

    # remove duplicates
    while len(dupes) > 0:
        dupe = dupes.pop()
        generator = filter(lambda k: isinstance(ctx.models[k[0]], model.model_t), dupe)

        try:
            keep = ctx.models[next(generator)[0]]
        except StopIteration:
            continue

        for old in generator:
            m = ctx.models[old[0]]
            keep, m = who_to_merge(keep, m)
            keep.merge_full(m, ctx)


""" Operands conflicts mitigation """

# get candidates common type
def get_common_type(candidates: list) -> model.model_type:
    ret = model.model_type.UNVALID
    for m, _ in candidates:
        if m.is_vtable():  # vtable
            current = model.model_type.VTABLE
        else:  # struct
            current = model.model_type.STRUCTURE

        if ret != model.model_type.UNVALID and current != ret:
            return model.model_type.UNVALID

        ret = current

    return ret


# less derived vtable or class
def find_less_derived(candidates: list, conflict_ea: int = 0):
    common_type = get_common_type(candidates)
    if common_type == model.model_type.STRUCTURE:
        return find_less_derived_class(candidates)

    if common_type == model.model_type.VTABLE:
        return find_less_derived_vtable(candidates)

    conflict_vtables = [i[0].get_name() for i in filter(lambda k: k[0].is_vtable(), candidates)]
    conflict_structs = [i[0].get_name() for i in filter(lambda k: not k[0].is_vtable(), candidates)]
    print(
        "Warning: conflict on 0x%x involves %d structures & %d vtables, %s <-> %s"
        % (
            conflict_ea,
            len(conflict_structs),
            len(conflict_vtables),
            str(conflict_structs[:4]),
            str(conflict_vtables[:4]),
        )
    )

    # choose between structs by default
    return find_less_derived_class([i for i in filter(lambda k: not k[0].is_vtable(), candidates)])


# between multiple candidates with a common base, find the one the closest from that common base
def find_less_derived_class(candidates: list):
    # 1: between the less shifted
    candidates.sort(key=lambda k: k[1])
    shift = candidates[0][1]
    selected = [i[0] for i in filter(lambda k: k[1] == shift, candidates)]

    # 2 sort by size
    selected.sort(key=lambda k: (k.size, k.sid))

    # 3: distinguish known size from unkown size
    known = [i for i in filter(lambda k: k.is_struct(), selected)]
    unknown = [i for i in filter(lambda k: k.is_varsize_struct(), selected)]

    if len(unknown) == 0:
        return (known[0], shift)

    # 4: unknown size structs in candidates, base choice on vtables
    if len(known) > 0 and 0 in known[0].vtables:  # prefer struct with vtable
        i = 0
        selected = known[0]
    else:
        i = 1
        selected = unknown[0]

    size = len(unknown)
    while i < size:
        # selected derives from unknown[i]
        if unknown[i].get_vtable(0) in selected.vtables[0][0:-1]:
            selected = unknown[i]
        i += 1

    return (selected, shift)


# find_less_derived but for vtables
def find_less_derived_vtable(candidates: list):
    out_vtbl, out_shift = candidates[0]

    i, size = 1, len(candidates)
    while i < size:

        most_derived = model.most_derived_vtable_from_cache(out_vtbl, candidates[i][0])
        if most_derived == out_vtbl:
            out_vtbl, out_shift = candidates[i]

        i += 1

    return (out_vtbl, out_shift)


# for all conflicts on operands, select which model (between all the candidates) the op will apply on
def select_operands_target(ctx: model.context_t):
    for (ea, n), (_, conflicts) in ctx.all_operands.items():
        if len(conflicts) > 1:
            candidates = [
                (ctx.models[sid], ctx.models[sid].get_shift_for_operand(ea, n)) for sid in conflicts
            ]
            selected = find_less_derived(candidates, ea)[0]

            dq = collections.deque()
            for sid in conflicts:
                if sid == selected.sid:
                    continue

                dq.append(sid)
                ctx.models[sid].operands.pop((ea, n))

            while len(dq) > 0:
                conflicts.remove(dq.pop())


""" Function arguments type conflicts """

# choose arg type between candidates
def select_argument_type(
    func: model.function_t, ctx: model.context_t, candidates: set, can_shift: bool = False
):
    if len(candidates) == 0:
        return None

    model, shift = find_less_derived(
        [(ctx.models[sid], shift) for sid, shift in candidates], func.ea
    )

    # do not apply shifted arg everywhere
    # avoid setting type fct(& A->int) for function fct(int* ptr)
    if shift != 0 and not can_shift:
        return None

    return (model, shift)


# purge arguments from structures arguments that should be sub-types
# ex: struc A {int a; ..} went into fct(int*) : fct(&A)
# we do not want to set the type as fct(A*), but let it as fct(int*)
def validate_function_arguments(fct: model.function_t):

    # set up function arguments
    state = cpustate.state_t()
    ctx = model.context_t()

    max_index = -1
    for i in range(fct.args_count):
        if fct.args[i] is not None:
            max_index = max(max_index, i)

            _, shift = fct.args[i]

            subject = model.model_t(-1, None, model.model_type.STRUCTURE_UKWN_SIZE)
            ctx.add_model(subject)
            cpustate.set_argument(fct.cc, state, i, cpustate.sid_t(subject.sid, shift))

            subject.sid = i

    # No need to compute when no args, or only *this args of virtual method
    if max_index < 0 or (max_index < 1 and fct.is_virtual):
        return

    # heuristic 1: if function is not widely used, type it with anything we have
    # genral functions that take primitive types have more references
    calls_count = len(ida_utils.get_references(fct.ea))
    if calls_count <= 3:  # arbitrary 3, to twist
        return

    # propagate arguments in function
    params = cpustate.propagation_param_t(depth=2)
    ida_fct = idaapi.get_func(fct.ea)
    if ida_fct is None:
        fct.discard_all_args()
        return

    for ea, cstate in cpustate.function_execution_flow(ida_fct, state, params):
        model.handle_access(cstate, ctx)

    # discard arguments that were not used
    for subject in ctx.get_models():
        index = subject.sid
        if fct.is_virtual and index == 0:  # we are sure about those
            continue

        original, _ = fct.args[index]

        # heuristic 2: discard structure argument when only the base of the structure was used
        subject.update_size()
        if subject.size <= 4 and original.size > subject.size:
            # print("function %x, arg %d (%s) was discarded" % (fct.ea, index, original.get_name()))
            fct.discard_arg(index)


# which type for functions arguments amoung multiple candidates
def select_functions_arguments(ctx: model.context_t):
    for function in ctx.functions.values():
        function.purge(ctx)

        for i in range(function.args_count):
            function.args[i] = select_argument_type(
                function, ctx, function.args[i], function.is_virtual and i == 0
            )

        function.ret = select_argument_type(function, ctx, function.ret)

        # validate selected arguments
        validate_function_arguments(function)


""" Solve all conflicts """

# Use conflict data to merge duplicated structures
def resolve_state_conflicts(ctx: model.context_t):
    conflicts_record = conflicts_t()

    # Generate conflict record from conflicting operands
    for key in ctx.all_operands:
        conflicts = ctx.all_operands[key]
        if len(conflicts[1]) > 1:
            conflicts_record.add_conflict(key[0], key[1], conflicts[0], conflicts[1], ctx)

    remove_duplicates(ctx, conflicts_record)


def get_unresolved_conflicts_count(ctx: model.context_t):
    count = 0
    for _, conflicts in ctx.all_operands.values():
        if len(conflicts) > 1:
            count += 1
    return count


# Solve all conflicts in the given model
def solve_conflicts(ctx: model.context_t, verbose: bool = True):

    # Select vtable owner
    for mod in ctx.get_models():
        if mod.is_vtable():
            select_vtable_owner(mod)

    if verbose:
        print("Info: conflicts count before resolution: %d" % get_unresolved_conflicts_count(ctx))

    # global conflicts
    resolve_state_conflicts(ctx)

    if verbose:
        print(
            "Info: conflicts count after model refactoring: %d"
            % get_unresolved_conflicts_count(ctx)
        )

    # select target for conflicting operands
    select_operands_target(ctx)

    if verbose:
        print(
            "Info: conflicts count after operands assignment: %d"
            % get_unresolved_conflicts_count(ctx)
        )

    # find arguments to apply to retrieved functions
    select_functions_arguments(ctx)
