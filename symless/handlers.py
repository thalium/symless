import os

import idaapi

import symless.utils as utils
from symless import conflict, existing, generation, model, symbols
from symless.cpustate import INSN_CALLS, arch, cpustate

RESOURCES_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "symless", "resources"))


# Form used to ask user which structure to propagate, which shift ..
class SelectionForm(idaapi.Form):
    def __init__(self):

        format = r"""STARTITEM {id:structChooser}
BUTTON YES* Propagate
BUTTON CANCEL Cancel
Structure propagation
{changeHandler}
<Choose a structure:{structChooser}>
<Shifted by:{shiftChooser}> | <##Advanced##spread in callees:{depthChooser}>{checkGroup}>
"""

        parameters = {
            "structChooser": idaapi.Form.EmbeddedChooserControl(StructureChooser()),
            "shiftChooser": idaapi.Form.NumericInput(tp=idaapi.Form.FT_DEC, value=0),
            "checkGroup": idaapi.Form.ChkGroupControl(("depthChooser",), value=1),
            "changeHandler": idaapi.Form.FormChangeCb(self.on_change),
        }

        # init form
        idaapi.Form.__init__(self, format, parameters)

    # selected structure
    def get_struc(self) -> idaapi.struc_t:
        selected = self.structChooser.selection
        if selected is None or len(selected) == 0:
            return None
        return idaapi.get_struc(idaapi.get_struc_by_idx(selected[0]))

    # selected shift
    def get_shift(self) -> int:
        return self.shiftChooser.value

    # selected depth
    def follow_callees(self) -> bool:
        return self.checkGroup.value == 1

    # on form modification
    def on_change(self, fid):
        # -1 seems to be gui creation
        if fid == -1 and StructureChooser.last_selection is not None:
            self.SetControlValue(self.structChooser, [StructureChooser.last_selection])

        # -2 seems to be the validate btn id
        elif fid == -2:
            selected = self.GetControlValue(self.structChooser)
            if selected is None or len(selected) == 0:
                idaapi.warning("Please select a structure")
                return -1

            # save last selected
            StructureChooser.last_selection = selected[0]

        return 1


# chooser for structure
class StructureChooser(idaapi.Choose):
    last_selection = None

    def __init__(self):
        idaapi.Choose.__init__(
            self, "", [["Structure", 10 | idaapi.CHCOL_PLAIN]], embedded=True, width=10, height=6
        )

    def OnGetLine(self, n):
        return [idaapi.get_struc_name(idaapi.get_struc_by_idx(n))]

    def OnGetSize(self):
        return idaapi.get_struc_qty()


# returns the register pointed by given address + associated operand
def target_op_reg(ea: int, op_num: int) -> (int, idaapi.op_t):
    insn = idaapi.insn_t()
    insn_len = idaapi.decode_insn(insn, ea)

    if insn_len == 0 or op_num < 0 or op_num >= len(insn.ops):
        return -1, None

    op = insn.ops[op_num]
    if op.type == idaapi.o_reg:
        return op.reg, op

    if op.type in [idaapi.o_phrase, idaapi.o_displ]:
        return cpustate.x64_base_reg(insn, op), op

    return -1, None


# Hook to attach new action to popup menu
class PopUpHook(idaapi.UI_Hooks):
    def __init__(self):
        idaapi.UI_Hooks.__init__(self)

        icon_path = os.path.join(RESOURCES_PATH, "propag.png")
        self.icon = idaapi.load_custom_icon(icon_path)

        self.action = idaapi.action_desc_t(
            "Symless:Live",
            "Propagate structure",
            BuildHandler(),
            "Shift+t",
            "Automatic t-t-t",
            self.icon,
            idaapi.ADF_OWN_HANDLER,
        )
        idaapi.register_action(self.action)

    def term(self):
        idaapi.unregister_action(self.action.name)
        idaapi.free_custom_icon(self.icon)

    # right click menu popup
    def finish_populating_widget_popup(self, widget, popup, ctx):
        # disassembly window + no selection + point at a register
        if (
            idaapi.get_widget_type(widget) == idaapi.BWN_DISASM
            and (ctx.cur_flags & idaapi.ACF_HAS_SELECTION) == 0
            and ((current_op_reg() >= 0) or current_ins_is_call())
        ):
            idaapi.attach_action_to_popup(widget, popup, self.action.name)


# Propagate & build structure action
class BuildHandler(idaapi.action_handler_t):
    def activate(self, ctx):
        reg_id, op = target_op_reg(ctx.cur_ea, idaapi.get_opnum())
        if reg_id < 0:
            insn = idaapi.insn_t()
            idaapi.decode_insn(insn, ctx.cur_ea)

            if insn.itype in INSN_CALLS and idaapi.get_opnum() >= 0:
                reg_id = 0  # rax return of malloc, etc.
                dst_op = False

            else:
                return 0
        else:

            # consider first operand to be the dst operand except if it is push
            dst_op = op.n == 0
            insn = idaapi.insn_t()
            idaapi.decode_insn(insn, ctx.cur_ea)

            if insn.itype == idaapi.NN_push:
                dst_op = False

        # arch supported
        if not arch.is_arch_supported():
            utils.logger.error("Unsupported arch (%s) or filetype" % arch.get_proc_name())
            return 0

        # convert to full register
        if reg_id in cpustate.X64_REG_ALIASES:
            reg_id = cpustate.X64_REG_ALIASES[reg_id]

        reg = cpustate.reg_string(reg_id)

        # params selections form
        form = SelectionForm()
        form.Compile()
        if form.Execute() <= 0:
            return 0  # cancel hit

        struc = form.get_struc()
        shift = form.get_shift()
        dive = form.follow_callees()

        form.Free()

        if struc is None:
            return 0

        idaapi.show_wait_box("Propagating struct info")

        try:
            context = propagate_struct(struc, ctx.cur_ea, reg, shift, dive, dst_op)
            if context is None:
                return 0

            # conflict resolution
            conflict.solve_conflicts(context)

            # use symbols for naming
            symbols.name_structures(context)

            # update idb
            generation.generate_struct(context.models[0], context)
            generation.set_functions_type(context.functions, False)

            # stats output
            utils.logger.info("Updated / created %d structures:" % len(context.models))
            for mod in context.get_models():
                utils.logger.info("  - %s" % mod.get_name())

        finally:
            idaapi.hide_wait_box()

        return 0

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# inject sid into propagated state
def injector(state: cpustate.state_t, ea: int, target_ea: int, target: str, value):
    if ea == target_ea:
        state.set_register_str(target, value)

        # also set previous value, for when it is accessed for dst operand
        state.set_register_str(target, value, 1)


# propagate and build one struct
def propagate_struct(
    struc: idaapi.struc_t, start_ea: int, target_reg: str, shift: int, dive: bool, on_dst_op: bool
) -> model.context_t:
    struc_model, context = existing.from_structure(struc)

    # inject after update if on dst operand, before update if on src operand
    def inject_cb(state, ea):
        return injector(state, ea, start_ea, target_reg, cpustate.sid_t(struc_model.sid, shift))

    inject = cpustate.injector_t(inject_cb, not on_dst_op)

    params = cpustate.propagation_param_t(inject, cpustate.MAX_PROPAGATION_RECURSION if dive else 0)

    func = idaapi.get_func(start_ea)
    if func is None:
        idaapi.warning("pointed address not part of a function")
        return None

    # propagate and update model
    for ea, state in cpustate.generate_state(func, params):
        model.handle_state(ea, state, context)

    # analyze vtables
    model.analyze_model_vtables(struc_model, params, context)

    # model size update
    struc_model.update_size()

    # visited functions
    context.update_functions(params.visited)

    return context


# current register pointed by cursor
def current_op_reg() -> int:
    current_ea = idaapi.get_screen_ea()
    current_op = idaapi.get_opnum()
    reg_id, _ = target_op_reg(current_ea, current_op)
    return reg_id


def current_ins_is_call() -> bool:
    current_ea = idaapi.get_screen_ea()
    current_op = idaapi.get_opnum()

    insn = idaapi.insn_t()
    idaapi.decode_insn(insn, current_ea)

    if insn.itype in INSN_CALLS and current_op >= 0:
        return True
    return False
