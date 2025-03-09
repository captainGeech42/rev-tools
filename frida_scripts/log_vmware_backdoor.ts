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

    // let ptr = args[0].readPointer();
    // if (ptr) {
    //     log(hexdump(ptr, { length: 0x30, ansi: false }));
    // } else {
    //     log("(couldnt deref mem)");
    // }
}

class Backdoor_proto_hb {
    rax: UInt64;
    rbx: UInt64;
    rcx: UInt64;
    rdx: UInt64;
    rsi: UInt64;
    rdi: UInt64;
    rbp: UInt64;

    constructor(ptr: NativePointer) {
        this.rax = ptr.readU64(); ptr = ptr.add(8);
        this.rbx = ptr.readU64(); ptr = ptr.add(8);
        this.rcx = ptr.readU64(); ptr = ptr.add(8);
        this.rdx = ptr.readU64(); ptr = ptr.add(8);
        this.rsi = ptr.readU64(); ptr = ptr.add(8);
        this.rdi = ptr.readU64(); ptr = ptr.add(8);
        this.rbp = ptr.readU64(); ptr = ptr.add(8);
    }

    toString(): string {
        return Object.entries(this).map(([k, v]) => `${k}=${v.toString(16)}`).join(" | ")
    }
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

    let ptr = args[0];

    log(`Backdoor_HbIn(${ptr.toString(16)})`);
    let bp = new Backdoor_proto_hb(ptr);
    log(`  ${bp}`);
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

    let ptr = args[0];

    log(`Backdoor_HbOut(${ptr.toString(16)})`);
    let bp = new Backdoor_proto_hb(ptr);
    log(`  ${bp}`);
}

const HOOKS = {
    // "Backdoor": Backdoor_OnEnter,
    "Backdoor_HbIn": BackdoorHbIn_OnEnter,
    "Backdoor_HbOut": BackdoorHbOut_OnEnter,
}

for (let [sym, hook] of Object.entries(HOOKS)) {
    Interceptor.attach(Module.getExportByName(MODULE_NAME, sym), {
        onEnter: hook
    })
}