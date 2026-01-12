import idaapi

import symless.cpustate.cpustate as cpustate
import symless.utils.ida_utils as ida_utils
import symless.utils.vtables as vtables
from symless.model import *
from symless.utils.utils import g_logger as logger

""" Propagation actions handlers """


# handle function ret, record ret type for function typing
def handle_ret(state: cpustate.state_t, ctx: context_t):
    if state.ret is None:
        return

    # only record struct pointer returned without shift
    if not isinstance(state.ret, cpustate.sid_t) or state.ret.shift != 0:
        return

    prot = ctx.get_function(state.get_fea())
    prot.set_ret(ctx.graph.get_entry_by_id(state.ret.sid))


# Build model members from state access
def handle_access(ea: int, sub_ea: int, state: cpustate.state_t, ctx: context_t):
    for access in state.accesses:
        struc = access.target

        # a structure is accessed
        if not isinstance(struc, cpustate.sid_t):
            continue

        offset = access.target.shift
        size = access.size

        # record field beeing accessed
        # do not make field for access of unknown (0) size
        entry = ctx.graph.get_entry_by_id(struc.sid)
        if size != 0:
            f = entry.add_field(offset, size)
            logger.debug(f"{ea:#x}.{sub_ea:x}: adding {f} to {entry.entry_id()}")

        # record operand for the access, to type later
        # we only care about regs operands
        if access.loc.t == ida_hexrays.mop_r:
            regid = ida_hexrays.mreg2reg(access.loc.r, access.loc.size)
            if regid == -1:  # special kreg, nothing to type
                return

            logger.debug(f"{ea:#x}.{sub_ea:x}: add operand to {entry.entry_id()} at offset 0x{offset:x}")
            entry.add_operand(ea, offset, regid)


# add arg_0 entry for each virtual method
# assuming every virtual method takes 'this' as first argument
# we are aware that in some cases this is not right ('this' unused by virtual method + optimization)
def analyze_virtual_methods(vtbl: vtables.vtable_t, current: entry_t, offset: int, ctx: context_t):
    if not ctx.can_follow_calls():
        return

    for fea, _ in vtbl.get_members():
        fct = idaapi.get_func(fea)
        if fct is None:  # no body for virtual method, it may be an import
            continue

        model = ctx.dflow_info.get_function(fct)

        # virtual method should have at least one argument (this)
        # if not we have no interest in analysing it
        if model is None or model.get_args_count() == 0:
            continue

        # add entry to analyse
        child = ctx.graph.add_entry_as_child(current, arg_entry_t(fea, 0), offset, False)
        if child is not None:
            logger.debug(f"Add virtual method 0x{fea:x}, {child.entry_id()}, as child of {current.entry_id()}")

        # mark function as virtual
        prot = ctx.get_function(fea)
        prot.set_virtual()


# Handle writes to struc members
def handle_write(ea: int, sub_ea: int, state: cpustate.state_t, ctx: context_t):
    ptr_size = ida_utils.get_ptr_size()

    for write in state.writes:
        struc = write.target
        size = write.size

        # mov [sid + offset], mem -> ptr loaded
        if not (isinstance(struc, cpustate.sid_t) and isinstance(write.value, cpustate.mem_t) and size == ptr_size):
            continue

        offset = struc.shift

        value = write.value.get_uval()
        entry = ctx.graph.get_entry_by_id(struc.sid)

        # check if addr is a vtable
        vtbl = vtables.vtable_t(value)

        # value is not a vtable address
        if not vtbl.valid():
            type = ftype_ptr_t(write.value)
            logger.debug(f'{ea:#x}.{sub_ea:x}: add type "{type}" to field 0x{offset:x} of {entry.entry_id()}')

        else:
            # record vtable loading sites
            # used later in conflicts to differentiate a base vtable from an inherinting one
            vtbl.search_loads()

            # get / create vtable entry point
            vtbl_entry = ctx.graph.add_entry(vtbl_entry_t(vtbl), True)
            type = ftype_struc_t(vtbl_entry)

            logger.debug(
                f"{ea:#x}.{sub_ea:x} associate {vtbl_entry.entry_id()} to field 0x{offset:x} of {entry.entry_id()}"
            )

            # add entrypoints to analyze virtual methods
            analyze_virtual_methods(vtbl, entry, offset, ctx)

        # type structure field with retrieved type
        entry.get_field(offset).set_type(type)


# Handle read of struct members
def handle_read(ea: int, sub_ea: int, state: cpustate.state_t, ctx: context_t):
    ptr_size = ida_utils.get_ptr_size()

    for read in state.reads:
        struc = read.target
        size = read.size

        # mov reg, [sid + offset]
        if not isinstance(struc, cpustate.sid_t):
            continue

        offset = struc.shift

        entry = ctx.graph.get_entry_by_id(struc.sid)

        # do not expand entries graph too much from read_entry_t leaves
        if isinstance(entry, read_entry_t):
            logger.debug(f"Ignoring read from {entry.entry_id()}")
            continue

        # no fixed value, propagate read entrypoint
        rtype = entry.get_field_type(offset)
        if rtype is None and size == ptr_size:
            r_entry = ctx.graph.add_entry(read_entry_t(ea, sub_ea, state.get_fea(), read.dst, entry, offset))
            logger.debug(f"{ea:#x}.{sub_ea:x}: type not known, propagating {r_entry.entry_id()}")

        elif rtype is None:
            pass

        # a struc ptr is read
        elif isinstance(rtype, ftype_struc_t):
            r_entry = ctx.graph.add_entry_as_child(
                rtype.entry, dst_var_entry_t(ea, sub_ea, state.get_fea(), read.dst), 0, False
            )
            if r_entry is not None:
                logger.debug(f"{ea:#x}.{sub_ea:x} from {rtype.entry.entry_id()}, propagating {r_entry.entry_id()}")

        # propagate any field
        else:
            state.set_var_from_mop(read.dst, rtype.get_propagated_value())
            logger.debug(f"{ea:#x}.{sub_ea:x}: propagating read type {rtype}")


# handle call, add entrypoints in callee
def handle_call(ea: int, sub_ea: int, state: cpustate.state_t, ctx: context_t):
    if not ctx.can_follow_calls():
        return

    if state.call_to is not None:
        ctx.dive_in = False  # default: do not dive in every callee
        call_ea = state.call_to.start_ea

        callee_model = ctx.dflow_info.get_function(state.call_to)
        if callee_model is None:
            return  # function mba could not be generated, analysis is not possible

        # callsite nargs can differ from callee nargs
        callee_nargs = min(len(state.call_args), callee_model.get_args_count())

        # look for entries to be propagated as callee's arguments
        epc = 0
        for i in range(callee_nargs):
            arg = state.call_args[i]

            if not isinstance(arg, cpustate.sid_t):
                continue

            entry = ctx.graph.get_entry_by_id(arg.sid)  # current entry as caller-to-callee arg

            # create new arg entry point
            # one entry point is restricted to be propagated in only one function
            epc += int(ctx.graph.add_entry_as_child(entry, arg_entry_t(call_ea, i), arg.shift, True) is not None)

        logger.debug(f"{ea:#x}.{sub_ea:x}, {epc} entrypoints recorded")


# handle new cpu state
def handle_state(ea: int, sub_ea: int, state: cpustate.state_t, ctx: context_t):
    handle_access(ea, sub_ea, state, ctx)
    handle_write(ea, sub_ea, state, ctx)
    handle_read(ea, sub_ea, state, ctx)
    handle_call(ea, sub_ea, state, ctx)
    handle_ret(state, ctx)


""" Entrypoints analysis & entries graph building """


# diving decision callback - dive if we have sid to propagate
def dive_in(callee: cpustate.function_t, state: cpustate.state_t, ctx: context_t) -> bool:
    dive = ctx.dive_in  # get context dive_in decision

    # root function, propagate
    if ctx.dflow_info.depth == ctx.dflow_info.max_depth:
        dive = True

    if dive:
        # arguments entries are to be built (again ?), reset their states
        for ep in ctx.graph.get_entries_at(callee.ea, -1, arg_entry_t.inject_before):
            ep.reset()
    utils.g_logger.debug("Diving into fct 0x%x: %s" % (callee.ea, "YES" if dive else "NO"))
    return dive


# injector callback, inject entrypoints into cpustate
def model_injector(state: cpustate.state_t, ea: int, sub_ea: int, before_update: bool, ctx: context_t):
    for ep in ctx.graph.get_entries_at(ea, sub_ea, before_update):
        utils.g_logger.debug(f"Injecting {ep.entry_id()} at {ea:#x}.{sub_ea:x}")
        ctx.dive_in |= ep.inject(state)  # dive in callee if new eps are to be analyzed


# entrypoints graph builder
# from original entrypoints, builds a propagation graph
# that can later be used to build structures
def analyze_entrypoints(ctx: context_t):
    entries = ctx.get_entrypoints()

    # injector callback
    def inject_cb(state: cpustate.state_t, ea: int, sub_ea: int, before_update: bool):
        model_injector(state, ea, sub_ea, before_update, ctx)

    inject = cpustate.injector_t(inject_cb, 3)

    # follow callees, use dive_in() decisions
    if ctx.can_follow_calls():
        ctx.dflow_info = cpustate.dflow_ctrl_t(inject, lambda callee, state: dive_in(callee, state, ctx))

    # only propagate in root function
    else:
        ctx.dflow_info = cpustate.dflow_ctrl_t(inject, lambda callee, state: dive_in(callee, state, ctx), depth=0)

    # analyse entrypoints by waves
    current_count = 1
    current_wave = 0
    while current_count > 0:
        current_count = 0
        for entry in entries.next_to_analyze():
            current_count += 1

            logger.debug(f"Analyzing entry {entry.entry_header()} ..")

            func = idaapi.get_func(entry.ea)
            for ea, sub_ea, state in cpustate.generate_state(func, ctx.dflow_info):
                handle_state(ea, sub_ea, state, ctx)

            # entrypoint was not injected
            # this happens when the user selects an entrypoint that gets deleted from the mba after call analysis
            # solution for now: let the user select another entrypoint, or update the mba
            if entry.to_analyze:
                logger.error(
                    f"Entry {entry.entry_header()} was not injected because it is unvalid - Redo the analysis."
                )
                current_count = 0
                break

        logger.debug(f"Entrypoints wave {current_wave} has been analyzed (total: {current_count})")
        current_wave += 1

    # remove propagation data from model
    del ctx.dflow_info
