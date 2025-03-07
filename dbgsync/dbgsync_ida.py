import ida_kernwin
import idaapi

import idalib.log

PLUGIN_NAME = "dbgsync"
PLUGIN_HOTKEY = "Ctrl+Alt+D"
PLUGIN_ACTION = "dbgsync:open"

LOG = idalib.log.Log(PLUGIN_NAME)

#################################################################

def entry():
    LOG("hello dbgsync")
    pass

#################################################################

class DbgsyncActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        super().__init__()
    
    def activate(self, ctx) -> int:
        entry()
        return 1
    
    def update(self, ctx) -> int:
        return ida_kernwin.AST_ENABLE_ALWAYS

class DbgsyncPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "dbgsync"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        # action = ida_kernwin.action_desc_t(
        #     PLUGIN_ACTION,
        #     "Debug IDAPython Script...",
        #     DbgsyncActionHandler(),
        #     PLUGIN_HOTKEY,
        #     None,
        #     # 199
        # )
        # ida_kernwin.register_action(action)

        # ida_kernwin.attach_action_to_menu("File/Script Command...", PLUGIN_ACTION, ida_kernwin.SETMENU_APP)

        LOG.success("dbgsync loaded, open with %s", PLUGIN_HOTKEY)

    def run(self, arg):
        entry()

    def term(self):
        pass

def PLUGIN_ENTRY() -> DbgsyncPlugin:
    return DbgsyncPlugin()

if __name__ == "__main__":
    DbgsyncPlugin().init()