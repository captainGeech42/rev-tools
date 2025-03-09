// vmtools!Backdoor
//      Backdoor_proto*
// vmtools!Backdoor_HbIn
//      Backdoor_proto_hb*
// vmtools!Backdoor_HbOut
//      Backdoor_proto_hb*

const MODULE_NAME = "vmtools.dll"

function Backdoor_OnEnter(args: InvocationArguments) {
    send(`Backdoor(${args[0].toString(16)})`);
}

function BackdoorHbIn_OnEnter(args: InvocationArguments) {
    send(`Backdoor_HbIn(${args[0].toString(16)})`);
}

function BackdoorHbOut_OnEnter(args: InvocationArguments) {
    send(`Backdoor_HbOut(${args[0].toString(16)})`);
}

const HOOKS = {
    "Backdoor": Backdoor_OnEnter,
    "Backdoor_HbIn": BackdoorHbIn_OnEnter,
    "Backdoor_HbOut": BackdoorHbOut_OnEnter,
}

for (let [sym, hook] of Object.entries(HOOKS)) {
    Interceptor.attach(Module.getExportByName(MODULE_NAME, sym), {
        onEnter: hook
    })
}