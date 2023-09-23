import ida_kernwin
import idaapi
import debugpy

import idalib.log

PLUGIN_NAME = "idapydbg"
PLUGIN_HOTKEY = "Ctrl+Alt+D"
PLUGIN_ACTION = "idapydbg:open"

LOG = idalib.log.Log("idapydbg")

#################################################################

class DebugSetupForm(ida_kernwin.Form):
    def __init__(self):
        self.invert = False
        

        super().__init__(r"""STARTITEM 0
BUTTON YES* Start Debug Server
BUTTON CANCEL Cancel
Setup IDAPyDbg Debugger

<##Select Python script:{iScriptPath}>
<##Debug server port   :{iPortNumber}>

        """, {
            "iScriptPath": ida_kernwin.Form.FileInput(open=True),
            "iPortNumber": ida_kernwin.Form.NumericInput(tp=ida_kernwin.Form.FT_UINT64)
        })

def dbg_entry():
    try:
        form = DebugSetupForm()
        form.Compile()
        ret = form.Execute()

        if ret == 1:
            LOG.info(form.iScriptPath.value)
            LOG.info(form.iPortNumber.value)
    except:
        LOG.exc("error generating form")

#################################################################

class DbgActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        super().__init__()
    
    def activate(self, ctx) -> int:
        dbg_entry()
        return 1
    
    def update(self, ctx) -> int:
        return ida_kernwin.AST_ENABLE_ALWAYS

class DbgPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "IDAPython Script Debugging"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ''

    def init(self):
        action = ida_kernwin.action_desc_t(
            PLUGIN_ACTION,
            "Debug IDAPython Script...",
            DbgActionHandler(),
            PLUGIN_HOTKEY,
            None,
            # 199
        )
        ida_kernwin.register_action(action)

        ida_kernwin.attach_action_to_menu("File/Script Command...", PLUGIN_ACTION, ida_kernwin.SETMENU_APP)

        LOG.success("IDAPyDbg loaded, start script debugging with %s", PLUGIN_HOTKEY)

    def run(self, arg):
        dbg_entry()

    def term(self):
        pass

def PLUGIN_ENTRY() -> DbgPlugin:
    return DbgPlugin()

if __name__ == "__main__":
    DbgPlugin().init()