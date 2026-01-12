import os
from collections import deque
from dataclasses import dataclass
from typing import Collection, Optional, Tuple

import ida_hexrays
import idaapi
from PyQt5 import QtCore, QtGui, QtWidgets

import symless
import symless.cpustate.arch as arch
import symless.generation.generate as generate
import symless.generation.structures as structures
import symless.model.model as model
import symless.utils.ida_utils as ida_utils
import symless.utils.utils as utils
from symless.plugins import *

# builder window title
WINDOW_TITLE = "Symless structure builder"

# fictive color_t used for tagging elements in our microcode view
COLOR_TARGET = idaapi.COLOR_OPND1
SCOLOR_TARGET = chr(COLOR_TARGET)


# Structure builder plugin extension
class BuilderPlugin(plugin_t):
    def __init__(self):
        self.uihook = PopUpHook()
        self.uihook.hook()

    def reload(self):
        self.uihook.init_action()

    def term(self):
        self.uihook.unhook()
        if self.uihook.loaded:
            self.uihook.term()


# retrieve the extension
def get_plugin() -> plugin_t:
    return BuilderPlugin()


# a selected micro-operand for data flow entrypoint
@dataclass
class mop_sel_t:
    ea: int  # insn ea
    sub_idx: int  # sub insn idx
    mop: ida_hexrays.mop_t  # selected mop
    as_dst: bool  # is dst operand

    def __str__(self) -> str:
        if self.mop.t == ida_hexrays.mop_r:
            name = ida_hexrays.get_mreg_name(self.mop.r, self.mop.size)
        elif self.mop.t == ida_hexrays.mop_S:
            name = f"stk:#{self.mop.s.off:x}"
        return f"{name} @ {self.ea:#x}.{self.sub_idx:x} ({'DST' if self.as_dst else 'SRC'})"


# context for parsing microinstruction and extracting operands
class minsn_parse_ctx_t:
    def __init__(self, mba: ida_hexrays.mba_t, ea: int):
        self.mba = mba
        self.ea = ea
        self.sub_idx = 0
        self.targets: Collection[mop_sel_t] = deque()

    def add_mop(self, mop: ida_hexrays.mop_t, as_dst: bool):
        self.targets.append(mop_sel_t(self.ea, self.sub_idx, ida_hexrays.mop_t(mop), as_dst))

    def next_subinsn(self):
        self.sub_idx += 1


# get simplified name for global at ea
# to be displayed in microcode view
def get_simplified_gbl_name(ea: int) -> str:
    d = ida_utils.demangle_ea(ea)
    if not len(d):
        return f"off_{ea:#x}"
    if "(" in d:
        return d.split("(")[0]
    return d


# parse a microcode operand
# returns its str representation & update the contained micro-operands in the context
# as_dst: operand value gets updated by the instruction
def parse_mop(ctx: minsn_parse_ctx_t, op: ida_hexrays.mop_t, as_dst: bool = False) -> Optional[str]:  # noqa: C901
    if op.t == ida_hexrays.mop_z:  # none
        return None

    if op.t == ida_hexrays.mop_r:  # micro register
        ctx.add_mop(op, as_dst)  # add as target variable
        return idaapi.COLSTR(idaapi.COLSTR(ida_hexrays.get_mreg_name(op.r, op.size), SCOLOR_TARGET), idaapi.SCOLOR_REG)

    if op.t == ida_hexrays.mop_n:  # immediate (number)
        return f"#{idaapi.COLSTR(hex(op.signed_value()), idaapi.SCOLOR_NUMBER)}"

    if op.t == ida_hexrays.mop_str:  # immediate (string)
        return f'"{idaapi.COLSTR(op.cstr, idaapi.SCOLOR_STRING)}"'

    if op.t == ida_hexrays.mop_d:  # result of another instruction
        in_repr = parse_minsn(ctx, op.d, True)
        ctx.next_subinsn()
        return in_repr

    if op.t == ida_hexrays.mop_S:  # local stack variable
        member = op.s.get_stkvar(None)
        if member in (None, -1):  # happens
            return idaapi.COLSTR(f"stk:#{op.s.off:x}", idaapi.SCOLOR_LOCNAME)
        ctx.add_mop(op, as_dst)

        if isinstance(member, int):  # IDA 9 API changed get_stkvar() prototype
            m = idaapi.udm_t()
            op.s.get_stkvar(m)
            varname = m.name

        # IDA 8 case
        else:
            varname = idaapi.get_member_name(member.id)

        return idaapi.COLSTR(idaapi.COLSTR(varname, SCOLOR_TARGET), idaapi.SCOLOR_LOCNAME)

    if op.t == ida_hexrays.mop_v:  # global variable
        color = idaapi.SCOLOR_DNAME
        if idaapi.get_func(op.g) is not None:
            color = idaapi.SCOLOR_CNAME
        return idaapi.COLSTR(get_simplified_gbl_name(op.g), color)

    if op.t == ida_hexrays.mop_b:  # micro basic block
        b = ctx.mba.get_mblock(op.b)
        assert b.serial == op.b
        return f"{b.start:#x}"  # type == BLT_STOP -> ret

    if op.t == ida_hexrays.mop_f:  # args list
        return f"({', '.join([parse_mop(ctx, i) for i in op.f.args])})"

    if op.t == ida_hexrays.mop_l:  # local variable
        return idaapi.COLSTR("?", idaapi.SCOLOR_LOCNAME)  # should only exist at MMAT_LVARS maturity

    if op.t == ida_hexrays.mop_a:  # address of operand
        return f"&({parse_mop(ctx, op.a)})"

    if op.t == ida_hexrays.mop_h:  # helper function
        return idaapi.COLSTR(op.helper, idaapi.SCOLOR_MACRO)

    if op.t == ida_hexrays.mop_c:  # mcases
        return idaapi.tag_remove(op.c._print())  # TODO test me

    if op.t == ida_hexrays.mop_fn:  # floating constant
        return idaapi.COLSTR(idaapi.tag_remove(op.fpc._print()), idaapi.SCOLOR_NUMBER)  # TODO test me

    if op.t == ida_hexrays.mop_p:  # operands pair
        return f"({parse_mop(ctx, op.pair.lop, as_dst)}, {parse_mop(ctx, op.pair.hop, as_dst)})"

    if op.t == ida_hexrays.mop_sc:  # scattered
        return op.scif.name  # TODO test me

    return "?"


# parse microcode instruction
# returns a str representation of the instruction + the variable it contains
# provides a simpler representation than the one given by insn._print()
def parse_minsn(ctx: minsn_parse_ctx_t, insn: ida_hexrays.minsn_t, inlined: bool = False) -> str:
    ops_repr = filter(
        lambda k: k is not None,
        [parse_mop(ctx, i, j) for (i, j) in ((insn.l, False), (insn.r, False), (insn.d, insn.modifies_d()))],
    )

    repr_ = None  # out string representation
    par_ = ("(", ")") if inlined else ("", "")
    padd = 0 if inlined else 9

    # call special format
    if insn.opcode == ida_hexrays.m_call:
        repr_ = f"{idaapi.COLSTR(ida_utils.g_mcode_name[insn.opcode], idaapi.SCOLOR_INSN):{' '}<{padd}} {next(ops_repr)}{next(ops_repr, '()')}"

    # special "ret" goto
    elif (
        insn.opcode == ida_hexrays.m_goto
        and insn.l.t == ida_hexrays.mop_b
        and ctx.mba.get_mblock(insn.l.b).type == ida_hexrays.BLT_STOP
    ):
        repr_ = idaapi.COLSTR("ret", idaapi.SCOLOR_INSN)

    # special embedded operations
    elif inlined and insn.d.t == ida_hexrays.mop_z:
        if insn.opcode == ida_hexrays.m_add:
            repr_ = f"{next(ops_repr)}+{next(ops_repr)}"
        elif insn.opcode == ida_hexrays.m_sub:
            repr_ = f"{next(ops_repr)}-{next(ops_repr)}"
        elif insn.opcode == ida_hexrays.m_mul:
            repr_ = f"{next(ops_repr)}*{next(ops_repr)}"
        elif insn.opcode == ida_hexrays.m_shl:
            repr_ = f"{next(ops_repr)}<<{next(ops_repr)}"
        elif insn.opcode == ida_hexrays.m_shr:
            repr_ = f"{next(ops_repr)}>>{next(ops_repr)}"
        elif insn.opcode == ida_hexrays.m_or:
            repr_ = f"{next(ops_repr)}|{next(ops_repr)}"
        elif insn.opcode == ida_hexrays.m_and:
            repr_ = f"{next(ops_repr)}&{next(ops_repr)}"
        elif insn.opcode == ida_hexrays.m_xor:
            repr_ = f"{next(ops_repr)}^{next(ops_repr)}"
        elif insn.opcode == ida_hexrays.m_ldx:
            repr_ = f"{next(ops_repr)}:{next(ops_repr)}"
            par_ = ("[", "]")

    # default repr
    if repr_ is None:
        repr_ = f"{idaapi.COLSTR(ida_utils.g_mcode_name[insn.opcode], idaapi.SCOLOR_INSN):{' '}<{padd}} {', '.join(ops_repr)}"

    # return insn representation within appropriate parentheses
    return f"{par_[0]}{repr_}{par_[1]}"


def find_in_line_wrapper(
    range: idaapi.tagged_line_section_t, line: idaapi.tagged_line_sections_t, tag: int
) -> idaapi.tagged_line_section_t:
    if hasattr(line, "find_in"):
        return line.find_in(range, tag)  # IDA 8
    return line.nearest_after(range, range.start, tag)  # IDA 9


# view of the current function (simplified) microcode
# for the user to select the propagation entry variable
class MicrocodeViewer(idaapi.simplecustviewer_t):
    def __init__(self, mba: ida_hexrays.mba_t, current_ea: int, hint: Tuple[int, int]):
        super().__init__()
        self.mba = mba
        guess_mreg, guess_size = hint  # guess for target variable

        # chosen target (insn ea, operand, is a dst operand ?)
        self.chosen: Optional[mop_sel_t] = None

        # list of valid target operands for each line
        self.ops_per_line: Collection[Optional[Collection[mop_sel_t]]] = list()

        self.Create("Symless microcode view")

        # fill view with microinstructions
        block = self.mba.blocks
        _jump = True
        while block:
            insn = block.head
            while insn:
                # print(idaapi.tag_remove(insn._print()))

                ctx = minsn_parse_ctx_t(self.mba, insn.ea)
                insn_repr = parse_minsn(ctx, insn)
                self.ops_per_line.append(ctx.targets)

                # set line in listing
                if _jump and insn.ea >= current_ea:
                    self.AddLine(f"{idaapi.COLSTR(hex(insn.ea), idaapi.SCOLOR_INSN)}  {insn_repr}")
                    self.Jump(self.Count() - 1)
                    _jump = False
                else:
                    self.AddLine(f"{idaapi.COLSTR(hex(insn.ea), idaapi.SCOLOR_PREFIX)}  {insn_repr}")

                # find target mvar from hint
                # if multiple mvar match hint, the last one is selected
                if insn.ea == current_ea and self.chosen is None:
                    for i, mvar in enumerate(ctx.targets):
                        if mvar.mop.t == ida_hexrays.mop_r and mvar.mop.r == guess_mreg and mvar.mop.size == guess_size:
                            self.set_chosen(self.Count() - 1, i)
                            break

                insn = insn.next
            block = block.nextb
            if block:  # basic block boundaries
                self.ops_per_line.append(None)  # account for empty lines
                self.AddLine("")

        # remove IDA status bar
        qwidget = idaapi.PluginForm.TWidgetToPyQtWidget(self.GetWidget())
        for child in qwidget.children():
            if isinstance(child, QtWidgets.QStatusBar):
                child.setMaximumHeight(0)

        qwidget.setMinimumWidth(512)

    # get index of given section in given line
    # use improper method because tagged_line_sections_t are not iterable in IDA python
    def index_of_sect_in_line(self, section: idaapi.tagged_line_section_t, line: idaapi.tagged_line_sections_t) -> int:
        range = idaapi.tagged_line_section_t()
        range.start = 0
        range.length = 0xFFFF

        # loop over the tagged sections of the line
        i = 0
        current = find_in_line_wrapper(range, line, COLOR_TARGET)
        while current and current.valid():
            if section.start == current.start and section.length == current.length:
                break
            i += 1
            range.start = current.start + current.length
            current = find_in_line_wrapper(range, line, COLOR_TARGET)
        return i

    # resfresh the view & try to disable (again) the default highlighting
    def OnCursorPosChanged(self):
        self.Refresh()
        idaapi.set_highlight(self.GetWidget(), None, idaapi.HIF_LOCKED)
        self.Close()

    # set chosen target variable to given (line, idx) variable
    def set_chosen(self, line: int, idx: int):
        # highligth selected var
        old_line = self.GetLine(line)[0]
        pat_off, pat_end = 0, 0
        for _ in range(idx + 1):
            pat_off = old_line.find(idaapi.SCOLOR_ON + SCOLOR_TARGET, pat_end, len(old_line))
            pat_end = old_line.find(idaapi.SCOLOR_OFF + SCOLOR_TARGET, pat_off, len(old_line)) + 2
        self.EditLine(
            line,
            old_line[:pat_off]
            + old_line[pat_off:pat_end].replace(SCOLOR_TARGET, idaapi.SCOLOR_ERROR)
            + old_line[pat_end:],
        )

        # set appropriate chosen
        self.chosen = self.ops_per_line[line][idx]
        utils.g_logger.debug(f"selected variable is {self.chosen}")

    # forget current selection
    def forget_chosen(self):
        for i in range(self.Count()):
            line = self.GetLine(i)[0]
            if idaapi.SCOLOR_ERROR in line:
                self.EditLine(i, line.replace(idaapi.SCOLOR_ERROR, SCOLOR_TARGET))
        self.Refresh()

        self.chosen = None

    # the user clicked (hopefully) a target variable
    def OnClick(self, shift):
        self.forget_chosen()  # clear any previous selection

        # click location
        loc = idaapi.listing_location_t()
        if not idaapi.get_custom_viewer_location(loc, self.GetWidget(), idaapi.CVLF_USE_MOUSE):
            return False

        # click location as coords
        y, x, _ = self.GetPos()

        # get clicked variable
        nearest = loc.tagged_sections.nearest_at(x, COLOR_TARGET)
        if nearest is None or not nearest.valid():
            return False

        # get variable idx in line
        var_idx = self.index_of_sect_in_line(nearest, loc.tagged_sections)

        self.set_chosen(y, var_idx)
        return True


"""
class StackViewer(idaapi.simplecustviewer_t):
    def __init__(self, fea: int):
        super().__init__()
        self.Create("Symless stack view")
        self.selected = None
        func = idaapi.get_func(fea)
        frame = idaapi.get_frame(func)
        if not frame:
            utils.g_logger.warning("No frame found")
            return
        self.items = []
        for offset, name, size in idautils.StructMembers(frame.id):
            # Get the member ID and type
            mptr: idaapi.member_t = idaapi.get_member_by_name(frame, name)
            tif = idaapi.tinfo_t()
            idaapi.get_member_tinfo(tif, mptr)
            mtype = idaapi.print_tinfo("", 0, 0, idaapi.PRTYPE_1LINE, tif, "", "")
            if mtype is None:
                mtype = "unknown"

            # Add the details to the items list
            self.items.append([hex(offset), name, hex(size), mtype])
            self.AddLine(
                f"{idaapi.COLSTR('rsp+0x{:04x}'.format(offset), idaapi.SCOLOR_KEYWORD)} "
                f"{idaapi.COLSTR(name.ljust(10), idaapi.SCOLOR_DNAME)} "
                f"{idaapi.COLSTR(mtype, idaapi.SCOLOR_NUMBER)}"
            )

        # remove status bar
        qwidget = idaapi.PluginForm.TWidgetToPyQtWidget(self.GetWidget())
        for child in qwidget.children():
            if isinstance(child, QtWidgets.QStatusBar):
                child.setMaximumHeight(0)
        qwidget.setMinimumWidth(384)

    def OnClick(self, shift):
        if self.selected is not None:
            line, _, _ = self.GetLine(self.selected)
            self.EditLine(self.selected, line[2:])

        line_no, x, y = self.GetPos()
        if line_no != self.selected:
            self.EditLine(line_no, f"> {self.GetCurrentLine()}")
            self.selected = line_no
            self.Refresh()
"""


# a line in the structures list
class StrucSelItem(QtWidgets.QListWidgetItem):
    def __init__(self, struc_name: str, size: int = 0):
        super().__init__(struc_name)
        self.name = struc_name
        self.size = size

    def get_name(self) -> str:
        return self.name

    def get_size(self) -> int:
        return self.size


# default option for structure selector
class StrucSelDefaultItem(QtWidgets.QListWidgetItem):
    def __init__(self):
        super().__init__("New structure")
        icon = QtGui.QIcon(os.path.join(os.path.abspath(symless.__path__[0]), "resources", "cross.png"))
        self.setIcon(icon)
        ft = QtGui.QFont()
        ft.setBold(True)
        self.setData(QtCore.Qt.FontRole, ft)

    def get_size(self) -> int:
        return 0


# structure selector (list)
class StrucSelWid(QtWidgets.QListWidget):
    def __init__(self, parent: QtWidgets.QWidget = None):
        super().__init__(parent)

        self.setWhatsThis("Select a structure to propagate.")

        # Get structures from local types
        tif = idaapi.tinfo_t()
        for id in range(1, idaapi.get_ordinal_count(None)):
            if tif.get_numbered_type(None, id) and (tif.is_struct() or tif.is_forward_struct()):
                local_type_name = idaapi.idc_get_local_type_name(id)
                self.addItem(StrucSelItem(local_type_name, 0 if tif.is_forward_struct() else tif.get_size()))
        self.sortItems()

        # default option
        default = StrucSelDefaultItem()
        self.insertItem(0, default)
        self.setCurrentItem(default)

    def sizeHint(self) -> QtCore.QSize:
        size = super().sizeHint()
        size.setHeight(256)
        return size


# base class for a tab in our plugin's UI
class BuilderTabBase(QtWidgets.QWidget):
    def __init__(self, window: "BuilderMainWid", parent: QtWidgets.QWidget = None):
        super().__init__(parent)
        self.window = window

    # get form error, None if well filled
    def get_error(self) -> Optional[str]:
        return None


"""
# tab - propagate structure in stack
class BuilderFromStkTab(BuilderTabBase):
    def __init__(self, fea: int, window: "BuilderMainWid", parent: QtWidgets.QWidget = None):
        super().__init__(window, parent)

        # title
        layout = QtWidgets.QVBoxLayout()
        title = QtWidgets.QLabel(self)
        title.setText("<h3>Select a stack offset</h3>")
        layout.addWidget(title)

        self.stack = StackViewer(fea)
        stackQTW = idaapi.PluginForm.TWidgetToPyQtWidget(self.stack.GetWidget())
        stackQTW.setWhatsThis("Choose the offset of your structure in the stack")
        layout.addWidget(stackQTW, QtCore.Qt.AlignLeft)

        # size selector
        self.size = QtWidgets.QLineEdit(self)
        self.size.setText("0x0")
        self.size.setMaxLength(16)
        self.size.setValidator(QtGui.QRegExpValidator(QtCore.QRegExp("^([0-9]+)|(0x[0-9a-fA-F]+)$"), self.size))
        self.size.setWhatsThis("Size of the in-stack structure.")
        lsize = QtWidgets.QLabel(self)
        lsize.setText("Structure size")
        lsize.setWhatsThis("Size of the in-stack structure.")
        lsize.setBuddy(self.size)

        # deep dive checkbox
        self.chk = QtWidgets.QCheckBox("Spread in callees", self)
        self.chk.setWhatsThis("Should propagation follow functions calls.")
        self.chk.setChecked(True)

        lcenter = QtWidgets.QHBoxLayout()
        lcenter.addWidget(lsize)
        lcenter.addWidget(self.size)
        lcenter.addStretch()
        lcenter.addWidget(self.chk)
        layout.addLayout(lcenter)

        self.setLayout(layout)

    def get_error(self) -> Optional[str]:
        if self.get_stack_offset() is None:
            return "Please select the offset of the structure in the stack."

        if self.get_structure_size() <= 0:
            return "Please provide a valid structure size."

        return None

    def get_stack_offset(self) -> Optional[int]:
        line_no = self.stack.selected
        if line_no is not None and line_no < len(self.stack.items):
            return int(self.stack.items[line_no][0], 16)
        return None

    def get_structure_size(self) -> int:
        sval = self.size.text()
        try:
            return int(sval, 16 if sval.startswith("0x") else 10)
        except ValueError:
            return -1

    def set_structure_size(self, size: int):
        self.size.setText(hex(size))
"""


# tab - propagate structure pointer
class BuilderFromPtrTab(BuilderTabBase):
    def __init__(
        self,
        mba: ida_hexrays.mba_t,
        ea: int,
        hint: Tuple[int, int],
        window: "BuilderMainWid",
        parent: QtWidgets.QWidget = None,
    ):
        super().__init__(window, parent)

        # title
        layout = QtWidgets.QVBoxLayout()
        title = QtWidgets.QLabel(self)
        title.setText("<h3>Select an entry variable</h3>")
        title.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(title)

        # microcode view
        self.microcodeViewer = MicrocodeViewer(mba, ea, hint)
        microQTW = idaapi.PluginForm.TWidgetToPyQtWidget(self.microcodeViewer.GetWidget())
        microQTW.setWhatsThis(
            "Select an entry point for the propagation. The entry point should be a variable having for value a pointer to the structure to propagate."
        )
        layout.addWidget(microQTW, QtCore.Qt.AlignLeft)

        # shift selector
        self.shift = QtWidgets.QLineEdit(self)
        self.shift.setText("0x0")
        self.shift.setMaxLength(16)
        self.shift.setValidator(QtGui.QRegExpValidator(QtCore.QRegExp("^([0-9]+)|(0x[0-9a-fA-F]+)$"), self.shift))
        self.shift.setWhatsThis("Shift to apply to the propagated structure pointer.")
        lshift = QtWidgets.QLabel(self)
        lshift.setText("Shifted by")
        lshift.setWhatsThis("Shift to apply to the propagated structure pointer.")
        lshift.setBuddy(self.shift)

        # deep dive checkbox
        self.chk = QtWidgets.QCheckBox("Spread in callees", self)
        self.chk.setWhatsThis("Should propagation follow functions calls.")
        self.chk.setChecked(True)

        lcenter = QtWidgets.QHBoxLayout()
        lcenter.addWidget(lshift)
        lcenter.addWidget(self.shift)
        lcenter.addStretch()
        lcenter.addWidget(self.chk)
        layout.addLayout(lcenter)

        self.setLayout(layout)

    def get_error(self) -> Optional[str]:
        if self.get_entry_variable() is None:
            return "Please provide a variable as an entry point for the propagation."

        if self.get_shift() < 0:
            return "Please provide a valid shift (negative values not supported)."

        return None

    def get_entry_variable(self) -> Optional[ida_hexrays.mop_t]:
        if self.microcodeViewer.chosen is None:
            return None
        return self.microcodeViewer.chosen.mop  # chosen op

    def get_shift(self) -> int:
        sval = self.shift.text()
        try:
            return int(sval, 16 if sval.startswith("0x") else 10)
        except ValueError:
            return -1


# plugin's main UI
class BuilderMainWid(QtWidgets.QDialog):
    def __init__(self, mba: ida_hexrays.mba_t, ea: int, hint: Tuple[int, int], parent: QtWidgets.QWidget = None):
        super().__init__(parent)
        self.mba = mba

        # main layout
        layout = QtWidgets.QVBoxLayout()

        # window's title
        whint = QtWidgets.QLabel(self)
        whint.setText("<h3>Select a structure</h3>")
        whint.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(whint)
        layout.setAlignment(whint, QtCore.Qt.AlignTop)

        # structure selector
        self.struct_selector = StrucSelWid(self)
        layout.addWidget(self.struct_selector, QtCore.Qt.AlignLeft)
        layout.setStretch(1, 1)

        # structure selector search bar
        self.search_bar = QtWidgets.QLineEdit(self)
        self.search_bar.setPlaceholderText("Structure name")
        self.search_bar.setWhatsThis("Name of the structure (new or existing) to propagate.")
        self.search_bar.textChanged.connect(self.search_for_structure)
        layout.addWidget(self.search_bar)
        self.search_bar.setFocus()

        # ctrl+f action
        saction = QtWidgets.QAction(self)
        saction.setShortcut(QtGui.QKeySequence.Find)
        saction.triggered.connect(self.search_for)
        self.addAction(saction)

        # tabs
        self.tabs = QtWidgets.QTabWidget(self)
        self.tabs.setMovable(False)
        self.tabs.setTabsClosable(False)
        self.tab0 = BuilderFromPtrTab(self.mba, ea, hint, self, self.tabs)
        self.tabs.addTab(self.tab0, "From pointer")
        # self.tab1 = BuilderFromStkTab(self.mba.entry_ea, self, self.tabs)
        # self.tabs.addTab(self.tab1, "From stack")
        layout.addWidget(self.tabs)
        layout.setStretch(3, 2)

        # Cancel & Propagate buttons
        lbottom = QtWidgets.QGridLayout()
        cancel_btn = QtWidgets.QPushButton("Cancel", self)
        cancel_btn.clicked.connect(self.reject)
        ok_btn = QtWidgets.QPushButton("Propagate", self)
        ok_btn.setDefault(True)
        ok_btn.clicked.connect(self.execute)
        lbottom.addWidget(cancel_btn, 0, 0)
        lbottom.addWidget(ok_btn, 0, 1)

        layout.addLayout(lbottom)
        layout.setAlignment(lbottom, QtCore.Qt.AlignBottom)
        self.setLayout(layout)

        # window's properties
        self.setWindowTitle(WINDOW_TITLE)

        # window's icon
        icon = QtGui.QIcon(os.path.join(os.path.abspath(symless.__path__[0]), "resources", "champi.png"))
        self.setWindowIcon(icon)

        # closing handler
        self.finished.connect(self.on_finish)

    def get_error(self) -> Optional[str]:
        struc = self.struct_selector.currentItem()

        if isinstance(struc, StrucSelDefaultItem) and len(self.search_bar.text()) == 0:
            return "Please provide a name for the new structure."

        return None

    # 'propagate' was clicked
    def execute(self):
        tab = self.tabs.currentWidget()
        error = self.get_error() or tab.get_error()

        if error is not None:
            idaapi.warning(error)
            return

        self.accept()

    # search for structure in list
    def search_for_structure(self, key: str):
        lkey = key.lower()
        for i in range(self.struct_selector.count()):
            current = self.struct_selector.item(i)
            current.setHidden(
                False if (not isinstance(current, StrucSelItem) or lkey in current.text().lower()) else True
            )

    # Ctrl+F action
    def search_for(self):
        self.search_bar.setFocus()

    # get structures (name) selected by user
    def get_structure(self) -> str:
        selected = self.struct_selector.currentItem()
        if isinstance(selected, StrucSelDefaultItem):
            return self.search_bar.text()

        return selected.get_name()

    # spread in callees checked by user
    def get_dive(self) -> bool:
        return self.tabs.currentWidget().chk.isChecked()

    # struc ptr shift specified by user
    def get_shift(self) -> int:
        tab = self.tabs.currentWidget()
        return tab.get_shift() if isinstance(tab, BuilderFromPtrTab) else 0

    # get the microcode variable the user selected as entry point
    def get_entry_variable(self) -> Optional[ida_hexrays.mop_t]:
        tab = self.tabs.currentWidget()
        return tab.get_entry_variable()

    # ea of the selected entry point
    def get_entry_ea(self) -> Tuple[int, int]:
        tab = self.tabs.currentWidget()
        return (
            (tab.microcodeViewer.chosen.ea, tab.microcodeViewer.chosen.sub_idx)
            if isinstance(tab, BuilderFromPtrTab)
            else (self.mba.entry_ea, 0)
        )

    # selected entry operand is a destination operand
    def entry_is_dst_op(self) -> bool:
        tab = self.tabs.currentWidget()
        return tab.microcodeViewer.chosen.as_dst if isinstance(tab, BuilderFromPtrTab) else False

    # close custom viewers when window is close
    # otherwise they will haunt IDA forever
    def on_finish(self, result):
        # TODO this does not seem to work
        # old views still appears in "Synchronize with"
        self.tab0.microcodeViewer.Close()
        # self.tab1.stack.Close()


# Hook to attach new action to popup menu
class PopUpHook(idaapi.UI_Hooks):
    loaded = False

    # triggered when all UI elements have been initialized
    def ready_to_run(self):
        self.init_action()

    def init_action(self):
        if self.loaded:
            return

        # check that the decompiler exists
        if not idaapi.init_hexrays_plugin():
            utils.g_logger.error("You do not have the decompiler for this architecture, symless will not load")
            self.unhook()
            return

        icon_path = os.path.join(utils.get_resources_path(), "propag.png")
        self.icon = idaapi.load_custom_icon(icon_path)

        self.action = idaapi.action_desc_t(
            "symless:live",
            "Propagate structure",
            BuildHandler(),
            "Shift+t",
            "Build structure from selected variable",
            self.icon,
            idaapi.ADF_OWN_HANDLER,
        )
        idaapi.register_action(self.action)
        self.loaded = True

    def term(self):
        idaapi.unregister_action(self.action.name)
        idaapi.free_custom_icon(self.icon)

    # triggered on right click menu popup
    def finish_populating_widget_popup(self, widget, popup, ctx: idaapi.action_ctx_base_t):
        # window is (DISASM or PSEUDOCODE) & no selection
        if ctx.widget_type not in (idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE) or ctx.has_flag(idaapi.ACF_HAS_SELECTION):
            return

        # we are inside a function
        if ctx.cur_func is None:
            return

        idaapi.attach_action_to_popup(widget, popup, self.action.name)


# context menu structure builder action
class BuildHandler(idaapi.action_handler_t):
    def activate(self, ctx: idaapi.action_ctx_base_t) -> int:
        hint_mreg = ida_hexrays.mr_none
        hint_size = 0

        if not arch.is_arch_supported():
            utils.g_logger.error("Unsupported arch (%s) or filetype" % arch.get_proc_name())
            return 0

        mba = ida_utils.get_func_microcode(ctx.cur_func, True)
        if not mba:
            utils.g_logger.error(f"Could not generate microcode for function {ctx.cur_func.start_ea:#x}")
            return 0

        # guess the micro operand associated to user selection
        if ctx.widget_type == idaapi.BWN_DISASM:
            hint_mreg, hint_size = self.guess_selected_mop_from_assembly()
        else:  # idaapi.BWN_PSEUDOCODE
            # TODO implement guessing for pseudocode view
            pass

        # display plugin's UI
        form = BuilderMainWid(mba, ctx.cur_ea, (hint_mreg, hint_size))
        code = form.exec()

        # cancel button was hit
        if code == QtWidgets.QDialog.Rejected:
            return 0

        propagate_structure(
            form.get_entry_ea(),
            form.get_entry_variable(),
            form.entry_is_dst_op(),
            form.get_structure(),
            form.get_shift(),
            form.get_dive(),
        )

        return 1  # all IDA windows will be refreshed

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

    # use the currently selected assembly operand to guess the corresponding microcode operand
    # returns (mreg_t, size)
    def guess_selected_mop_from_assembly(self) -> Tuple[int, int]:
        mreg = ida_hexrays.mr_none
        mreg_size = 0

        cur_ea = idaapi.get_screen_ea()  # current address
        cur_op = idaapi.get_opnum()  # current op idx
        cur_insn = idaapi.insn_t()  # current instruction
        insn_len = idaapi.decode_insn(cur_insn, cur_ea)

        if insn_len == 0 or cur_op < 0 or cur_op > ida_utils.get_len_insn_ops(cur_insn):
            return (mreg, mreg_size)

        op = cur_insn.ops[cur_op]
        if op.type == idaapi.o_reg:
            mreg = ida_hexrays.reg2mreg(op.reg)  # mr_none if none
            mreg_size = idaapi.get_dtype_size(op.dtype)

        elif op.type in [idaapi.o_phrase, idaapi.o_displ]:
            mreg = ida_hexrays.reg2mreg(op.phrase)
            mreg_size = ida_utils.get_ptr_size()

        if mreg_size:
            utils.g_logger.debug(f"Guess for target mreg: {ida_hexrays.get_mreg_name(mreg, mreg_size)}")

        return (mreg, mreg_size)


# do the propagation & build the structure
def propagate_structure(
    ea_couple: Tuple[int, int], mop: ida_hexrays.mop_t, dst_op: bool, strucname: str, shift: int, dive: bool
):
    idaapi.show_wait_box("HIDECANCEL\nPropagating struct info..")

    ea, subea = ea_couple

    try:
        # get containing function
        fct = idaapi.get_func(ea)

        # entry is to be injected after minsn is processed
        if dst_op:
            entry = model.dst_var_entry_t(ea, subea, fct.start_ea, mop)

        # entry is to be injected before
        else:
            entry = model.src_reg_entry_t(ea, subea, fct.start_ea, mop)

        entry.struc_shift = shift  # shift for associated structure

        # set root entries
        entries = model.entry_record_t()
        entries.add_entry(entry, True)

        # build entrypoints graph
        ctx = model.context_t(entries, set())
        ctx.set_follow_calls(dive)
        model.analyze_entrypoints(ctx)

        # define structures
        strucs = structures.define_structures(ctx)

        # associate generated model with chosen structure
        _, struc_model = entry.get_structure()
        if struc_model is None:
            pass  # previous steps have failed (hopefully with an error msg)

        else:
            struc_model.set_name(strucname)
            struc_model.force_generation = True  # generate even if empty

            # make sure not to reduce existing structure size by removing padding
            struc = ida_utils.get_local_type(strucname)
            if struc and not struc.is_forward_decl() and struc.get_size() > struc_model.get_size():
                struc_model.set_size(struc.get_size())

            # import structures into IDA
            generate.import_structures(strucs)

            # type operands with structures
            generate.import_context(ctx)

    except Exception as e:
        import traceback

        utils.g_logger.critical(repr(e) + "\n" + traceback.format_exc())

    finally:
        # no need to keep all mbas
        ida_utils.g_microcode_cache.clear()

        idaapi.hide_wait_box()
