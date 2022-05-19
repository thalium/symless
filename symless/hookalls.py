import idaapi

import symless.utils as utils
from symless import cpustate
from symless.config.custom_hooks import call_hooks


def hook_call(callee_addr: int, state: cpustate.state_t, insn: idaapi.insn_t) -> bool:

    # TODO : Not efficient at all, better to use two hashmaps, addr and str
    for addr_call_hook, name_call_hook in call_hooks:

        if callee_addr == addr_call_hook or idaapi.get_name(callee_addr) == name_call_hook:
            utils.logger.critical(f"hook {hex(addr_call_hook)}/{name_call_hook} at {hex(insn.ea)}")
            regs_to_update = call_hooks[(addr_call_hook, name_call_hook)]
            for reg_str in regs_to_update:
                state.set_register_str(reg_str, state.get_register_str(regs_to_update[reg_str]))
                return True

    return False
