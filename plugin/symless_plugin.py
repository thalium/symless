import importlib
import os

import idaapi

import symless
import symless.config.settings as settings
import symless.main as symless_main
import symless.utils.utils as utils
from symless.plugin.handlers import PopUpHook


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
        settings.settings = settings.load_settings()
        utils.logger = utils.set_logger()

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
        importlib.reload(symless.config.settings)
        importlib.reload(symless.cpustate)
        importlib.reload(symless.cpustate.arch)
        importlib.reload(symless.cpustate.cpustate)
        importlib.reload(symless.conflict)
        importlib.reload(symless.existing)
        importlib.reload(symless.generation)
        importlib.reload(symless.model)
        importlib.reload(symless.symbols)
        importlib.reload(symless.utils.ida_utils)
        importlib.reload(symless.main)
        importlib.reload(symless.utils.utils)
        importlib.reload(symless.allocators)
        importlib.reload(symless.plugin.handlers)
        importlib.reload(symless.hookalls)

        self.load()

        symless_main.start_analysis(
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "../symless/config/imports.csv"
            )
        )


def PLUGIN_ENTRY():
    return SymlessPlugin()
