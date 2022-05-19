import importlib
import os

import idaapi

import symless
import symless.settings
import symless.utils
from symless import symless_action
from symless.handlers import PopUpHook


# Symless plugin
class SymlessPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_MOD | idaapi.PLUGIN_PROC
    comment = "Structure information propagation & building"
    help = "Propagate one struct information through assembly code"
    wanted_name = "Symless"
    wanted_hotkey = "ctrl+shift+s"

    def load(self):
        self.uihook = PopUpHook()
        self.uihook.hook()
        symless.settings.settings = symless.settings.load_settings()
        symless.utils.logger = symless.utils.set_logger()

    def init(self):
        self.load()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.reload_plugin()
        pass

    def term(self):
        self.uihook.term()
        self.uihook.unhook()

    def reload_plugin(self):

        self.uihook.term()
        self.uihook.unhook()

        importlib.reload(symless)
        importlib.reload(symless.settings)
        importlib.reload(symless.cpustate)
        importlib.reload(symless.cpustate.arch)
        importlib.reload(symless.cpustate.cpustate)
        importlib.reload(symless.conflict)
        importlib.reload(symless.existing)
        importlib.reload(symless.generation)
        importlib.reload(symless.model)
        importlib.reload(symless.symbols)
        importlib.reload(symless.ida_utils)
        importlib.reload(symless.symless_action)
        importlib.reload(symless.utils)
        importlib.reload(symless.allocators)
        importlib.reload(symless.handlers)
        importlib.reload(symless.hookalls)

        self.load()

        symless_action.symless_analyse(
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "../symless/config/imports.csv"
            )
        )


def PLUGIN_ENTRY():
    return SymlessPlugin()
