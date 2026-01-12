import copy
import enum
from typing import Collection, Dict, Generator, List, Optional

import ida_hexrays
import idaapi

import symless.utils.ida_utils as ida_utils
import symless.utils.utils as utils

########################
# CPU state definition #
########################


# abstract operand - define a micro-operand type & possible value
# use to track values propagation between variables
class absop_t:
    # should this operand value be transfered from a caller to a callee as an arg
    def should_dive(self) -> bool:
        return True

    def __eq__(self, other) -> bool:
        raise Exception('Class "%s" should implement __eq__()' % self.__class__.__name__)

    def __hash__(self) -> int:
        raise Exception('Class "%s" should implement __hash__()' % self.__class__.__name__)


# return value of an unknown call
class call_t(absop_t):
    def __init__(self, arg: int, where: int):
        self.arg = arg
        self.where = where

    def __eq__(self, other) -> bool:
        return isinstance(other, call_t) and self.where == other.where and self.arg == other.arg

    def __hash__(self) -> int:
        return self.where

    def __repr__(self):
        return f"call:0x{self.arg:x}@0x{self.where:x}"


# (unknown) function argument operand
class arg_t(absop_t):
    def __init__(self, idx: int):
        self.idx = idx

    def should_dive(self) -> bool:
        return False  # one caller arg is not a callee arg

    def __eq__(self, other) -> bool:
        return isinstance(other, arg_t) and self.idx == other.idx

    def __hash__(self) -> int:
        return self.idx

    def __repr__(self):
        return "arg%d" % self.idx


# shifted buffer
class buff_t(absop_t):
    def __init__(self, shift: int = 0):
        self.shift = shift

    def shift_by(self, add: int, size: int) -> "buff_t":
        out = copy.copy(self)
        out.shift = utils.to_c_integer(out.shift + add, size)
        return out


# a pointer dereference (ex: access to an object's field)
class deref_t(absop_t):
    def __init__(self, ptr: Optional[absop_t], size: int):
        self.ptr = ptr  # pointer beeing dereferenced
        self.size = size

    def __eq__(self, other) -> bool:
        return isinstance(other, deref_t) and self.ptr == other.ptr and self.size == other.size

    def __hash__(self) -> int:
        return hash((self.ptr, self.size))

    def __repr__(self):
        return f"[{self.ptr}:{self.size:#x}]"


# structure pointer
class sid_t(buff_t):
    def __init__(self, sid, shift=0):
        super().__init__(shift)
        self.sid = sid

    def should_dive(self) -> bool:
        return False  # sid represents an entrypoint -> local to a function

    def __eq__(self, other) -> bool:
        return isinstance(other, sid_t) and self.sid == other.sid and self.shift == other.shift

    def __hash__(self) -> int:
        return hash((self.sid, self.shift))

    def __repr__(self):
        return f"sid{self.sid:x}+0x{self.shift:x}"


# immediate operand, applies to the same operation than buff_t
class int_t(buff_t):
    def __init__(self, val: int, sizeof: int):
        super().__init__(val)

        self.size = sizeof
        self.shift = utils.to_c_integer(self.shift, self.size)

    def get_val(self) -> int:
        return self.shift

    def get_uval(self) -> int:  # unsigned value
        return utils.to_c_integer(self.shift, self.size, False)

    def __eq__(self, other) -> bool:
        return isinstance(other, int_t) and self.shift == other.shift and self.size == other.size

    def __hash__(self) -> int:
        return hash((self.shift, self.size))

    def __repr__(self):
        return f"int{self.size*8}:0x{self.get_uval():x}"


# a memory address or a value read @ addr
class mem_t(int_t):
    def __init__(self, value: int, addr: int, sizeof: int):
        super().__init__(value, sizeof)
        self.addr = addr

    def __repr__(self):
        return f"mem:0x{self.addr:x}:0x{self.get_uval():x}"


# memory write
class write_t:
    def __init__(self, ea: int, target: Optional[absop_t], size: int, value: Optional[absop_t]):
        self.ea = ea  # ea of the write
        self.target = target  # write dst
        self.size = size  # write size
        self.value = value  # written value

    def __repr__(self):
        return f"{self.ea:#x} u{self.size*8}[{self.target}]={self.value}"


# memory read
class read_t:
    def __init__(self, ea: int, target: Optional[absop_t], size: int, dst: ida_hexrays.mop_t):
        self.ea = ea  # ea of the read
        self.target = target  # read src
        self.size = size  # read size
        self.dst = dst  # dst operand of the read, no copy

    def __repr__(self):
        dstname = (
            ida_hexrays.get_mreg_name(self.dst.r, self.size)
            if self.dst.t == ida_hexrays.mop_r
            else f"stk:{self.dst.s.off:x}"
        )
        return f"{self.ea:#x} {dstname}=u{self.size*8}[{self.target}]"


# memory access
class access_t:
    def __init__(self, ea: int, target: Optional[absop_t], loc: idaapi.mop_t, size: int):
        self.ea = ea  # ea for the access
        self.target = target  # target beeing accessed
        self.size = size  # access size
        self.loc = loc  # target operand, no copy it should not get freed

    def __repr__(self):
        return f"{self.ea:#x} u{self.size*8}[{self.target}]"


# a visited function
class function_t:
    def __init__(self, mba: ida_hexrays.mba_t):
        self.ea = mba.entry_ea

        # location of function's ret code
        self.retloc: Optional[ida_hexrays.vdloc_t] = None

        # location of function's arguments
        self.argloc: Collection[ida_hexrays.vdloc_t] = list()

        # tinfo for function, force decompile for accurate arguments count
        finfo = ida_utils.get_fct_type(self.ea, True)
        if not finfo:
            return

        fdata = idaapi.func_type_data_t()
        if not finfo.get_func_details(fdata):
            utils.g_logger.warning(f"No func_details for fea {self.ea:#x}")
            return

        # update retloc & arglocs
        if fdata.retloc.atype() != idaapi.ALOC_NONE:
            self.retloc = mba.idaloc2vd(fdata.retloc, ida_utils.get_ptr_size())

        for arg in fdata:
            self.argloc.append(mba.idaloc2vd(arg.argloc, ida_utils.get_ptr_size()))

    def get_args_count(self) -> int:
        return len(self.argloc)

    def get_retloc(self) -> Optional[ida_hexrays.vdloc_t]:
        return self.retloc

    def get_argloc(self, idx: int) -> Optional[ida_hexrays.vdloc_t]:
        if idx < self.get_args_count():
            return self.argloc[idx]
        return None

    def __repr__(self):
        return f"fct {hex(self.ea)} ({self.get_args_count()} args)"


# types for state last processed instruction
class last_insn_type_t(enum.Enum):
    LAST_INSN_ANY = 0
    LAST_INSN_RET = 1
    LAST_INSN_CALL = 2


# a cpu state (stack, registers (variables), ..)
class state_t:
    def __init__(self, mba: ida_hexrays.mba_t, fct: Optional[function_t]):
        self.mba = mba  # microcode where the propagation takes place
        self.fct = fct  # owning function's model

        # type of the last processed instruction
        # we mostly care about function calls & ret
        self.last_insn_type: last_insn_type_t = last_insn_type_t.LAST_INSN_ANY

        # record current micro registers values (mreg_t: value)
        self.registers: Dict[int, absop_t] = {}

        # record current stack variables values (index: value)
        self.locals: Dict[int, absop_t] = {}

        self.writes: List[write_t] = []  # writes performed by last insn
        self.reads: List[read_t] = []  # reads performed by last insn
        self.accesses: List[access_t] = []  # memory accesses performed by last insn

        self.call_to: Optional[idaapi.func_t] = None  # current call target
        self.call_args: List[Optional[absop_t]] = []  # arguments for current call insn

        self.ret: Optional[absop_t] = None  # current ret value

    # start ea for function in which we propagate
    def get_fea(self) -> int:
        return self.fct.ea

    # get value for given mreg_t
    def get_register(self, mreg: int) -> Optional[absop_t]:
        return self.registers.get(mreg)

    # set value for mreg_t
    def set_register(self, mreg: int, value: Optional[absop_t]):
        if value is not None:
            self.registers[mreg] = value
        else:
            self.drop_register(mreg)

    # drop recorded value for mreg_t
    def drop_register(self, mreg: int):
        self.registers.pop(mreg, None)

    # get value for given stack variable
    def get_local(self, idx: int) -> Optional[absop_t]:
        return self.locals.get(idx)

    # set value for stack variable
    def set_local(self, idx: int, value: Optional[absop_t]):
        if value is not None:
            self.locals[idx] = value
        else:
            self.drop_local(idx)

    # drop recorded stack variable
    def drop_local(self, idx: int):
        self.locals.pop(idx, None)

    # get value for given micro operand
    def get_var_from_mop(self, mop: ida_hexrays.mop_t) -> Optional[absop_t]:
        if mop.t == ida_hexrays.mop_r:
            return self.get_register(mop.r)
        if mop.t == ida_hexrays.mop_S:
            return self.get_local(mop.s.off)
        utils.g_logger.warning(f"{ida_utils.g_mopt_name[mop.t]} operands not handled")
        return None

    # set value for given micro operand
    def set_var_from_mop(self, mop: ida_hexrays.mop_t, value: Optional[absop_t]):
        if mop.t == ida_hexrays.mop_r:
            self.set_register(mop.r, value)
        elif mop.t == ida_hexrays.mop_S:
            self.set_local(mop.s.off, value)
        else:
            utils.g_logger.error(f"{ida_utils.g_mopt_name[mop.t]} operands not handled")

    # drop var from given micro operand
    def drop_var_from_mop(self, mop: ida_hexrays.mop_t):
        if mop.t == ida_hexrays.mop_r:
            self.drop_register(mop.r)
        elif mop.t == ida_hexrays.mop_S:
            self.drop_local(mop.s.off)
        else:
            utils.g_logger.info(f"{ida_utils.g_mopt_name[mop.t]} operands not handled")

    # get value at the specified vd location (stack or register)
    def get_var_from_loc(self, loc: ida_hexrays.vdloc_t) -> Optional[absop_t]:
        if loc.is_reg1():
            return self.get_register(loc.reg1())
        if loc.is_stkoff():
            return self.get_local(loc.stkoff())
        return None

    # set value at the specified vd location (stack or register)
    def set_var_from_loc(self, loc: ida_hexrays.vdloc_t, value: Optional[absop_t]):
        if loc.is_reg1():
            self.set_register(loc.reg1(), value)
        elif loc.is_stkoff():
            self.set_local(loc.stkoff(), value)

    # drop recorded values for kregs used to pass results between inlined minsns
    def drop_kregs(self):
        for kreg in self.mba.tmp_result_kregs:
            self.drop_register(kreg)
        self.drop_register(self.mba.call_result_kreg)

    def get_vars(self) -> Generator[absop_t, None, None]:
        for var in self.registers.values():
            yield var
        for var in self.locals.values():
            yield var

    def get_nb_types(self, wanted_type) -> int:
        ret = 0
        for var in self.get_vars():
            ret += int(isinstance(var, wanted_type))
        return ret

    # reset information about current insn
    def reset(self):
        self.last_insn_type = last_insn_type_t.LAST_INSN_ANY
        self.writes.clear()
        self.reads.clear()
        self.accesses.clear()
        self.call_to = None
        self.call_args.clear()
        self.ret = None

    # copy persistent content into another state
    def copy(self) -> "state_t":
        out = state_t(self.mba, self.fct)
        out.registers = copy.copy(self.registers)
        out.locals = copy.copy(self.locals)
        return out

    # save write
    def write_to(self, ea: int, target: Optional[absop_t], loc: idaapi.mop_t, size: int, value: Optional[absop_t]):
        self.access_to(ea, target, loc, size)
        self.writes.append(write_t(ea, target, size, value))

    # save read
    def read_from(self, ea: int, target: Optional[absop_t], loc: idaapi.mop_t, size: int, dst: ida_hexrays.mop_t):
        self.access_to(ea, target, loc, size)
        self.reads.append(read_t(ea, target, size, dst))

    # save access
    def access_to(self, ea: int, target: Optional[absop_t], loc: idaapi.mop_t, size: int):
        self.accesses.append(access_t(ea, target, loc, size))

    # state contains call info from last call instruction
    def has_call_info(self) -> bool:
        return self.last_insn_type == last_insn_type_t.LAST_INSN_CALL

    # state contains ret info from last function ret
    def has_ret_info(self) -> bool:
        return self.last_insn_type == last_insn_type_t.LAST_INSN_RET

    # cpu state representation
    def __repr__(self) -> str:
        regs = ", ".join([f"{idaapi.get_mreg_name(r, 8)}({v})" for r, v in self.registers.items()])
        lcls = ", ".join([f"{loc:#x}({val})" for loc, val in sorted(self.locals.items(), key=lambda k: k[0])])
        return f"[regs: {regs}], [stack: {lcls}]"
