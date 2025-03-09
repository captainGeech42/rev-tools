const log = console.log

// vmtools!Backdoor
//      Backdoor_proto*
// vmtools!Backdoor_HbIn
//      Backdoor_proto_hb*
// vmtools!Backdoor_HbOut
//      Backdoor_proto_hb*

const MODULE_NAME = "vmtools.dll"

function Backdoor_OnEnter(args: InvocationArguments) {
    /*
    mov     rax, rcx
    push    rax
    mov     rdi, [rax+28h]
    mov     rsi, [rax+20h]
    mov     rdx, [rax+18h]
    mov     rcx, [rax+10h]
    mov     rbx, [rax+8]
    mov     rax, [rax]
    in      eax, dx
    xchg    rax, [rsp+20h+var_20]
    mov     [rax+28h], rdi
    mov     [rax+20h], rsi
    mov     [rax+18h], rdx
    mov     [rax+10h], rcx
    mov     [rax+8], rbx
    pop     qword ptr [rax]
    */
    log(`Backdoor(${args[0].toString(16)})`);
    log(hexdump(args[0].readPointer(), { length: 0x30, ansi: false }))
}

function BackdoorHbIn_OnEnter(args: InvocationArguments) {
    /*
    mov     rax, rcx
    push    rax
    mov     rbp, [rax+30h]
    mov     rdi, [rax+28h]
    mov     rsi, [rax+20h]
    mov     rdx, [rax+18h]
    mov     rcx, [rax+10h]
    mov     rbx, [rax+8]
    mov     rax, [rax]
    cld
    rep insb
    xchg    rax, [rsp+28h+var_28]
    mov     [rax+30h], rbp
    mov     [rax+28h], rdi
    mov     [rax+20h], rsi
    mov     [rax+18h], rdx
    mov     [rax+10h], rcx
    mov     [rax+8], rbx
    pop     qword ptr [rax]
    */
    log(`Backdoor_HbIn(${args[0].toString(16)})`);
}

function BackdoorHbOut_OnEnter(args: InvocationArguments) {
    /*
    mov     rax, rcx
    push    rax
    mov     rbp, [rax+30h]
    mov     rdi, [rax+28h]
    mov     rsi, [rax+20h]
    mov     rdx, [rax+18h]
    mov     rcx, [rax+10h]
    mov     rbx, [rax+8]
    mov     rax, [rax]
    cld
    rep outsb
    xchg    rax, [rsp+28h+var_28]
    mov     [rax+30h], rbp
    mov     [rax+28h], rdi
    mov     [rax+20h], rsi
    mov     [rax+18h], rdx
    mov     [rax+10h], rcx
    mov     [rax+8], rbx
    pop     qword ptr [rax]
    */
    log(`Backdoor_HbOut(${args[0].toString(16)})`);
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