const log = console.log

const MODULE_NAME = "vmtools.dll"

function Backdoor_OnEnter(this: InvocationContext, args: InvocationArguments) {
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
        return Object.entries(this).map(([k, v]) => `${k}=0x${v.toString(16)}`).join(" | ")
    }

    data(): ArrayBuffer | null {
        let ptr = new NativePointer(this.rsi);

        // log(JSON.stringify(Process.getRangeByAddress(ptr)));
        // return null;

        return ptr.readByteArray(this.rcx.toNumber());
    }

    isCmdMsg(): boolean {
        return this.rbx.and(0xff).equals(0);
    }
}


function BackdoorHbIn_OnLeave(this: InvocationContext, retval: InvocationReturnValue) {
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

    log(`Backdoor_HbIn() -> ${retval.toString(16)}`);
    let bp = new Backdoor_proto_hb(retval);
    log(`  ${bp}`);

    if (!bp.isCmdMsg()) {
        log(`  not a msg`);
        return;
    }

    let data = bp.data();
    if (data) {
        log(hexdump(data));
    }

    // log(JSON.stringify(this.context));
}

function BackdoorHbOut_OnEnter(this: InvocationContext, args: InvocationArguments) {
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

    let data = bp.data();
    if (data) {
        log(hexdump(data));
    }

    log("\r\n\r\n-------------------\r\n");
}

// in == host->guest
// out == guest->host
// so, intercept out before the call, and in after
const HOOKS = {
    // "Backdoor": [Backdoor_OnEnter, undefined],
    "Backdoor_HbIn": { enter: undefined, leave: BackdoorHbIn_OnLeave },
    "Backdoor_HbOut": { enter: BackdoorHbOut_OnEnter, leave: undefined },
}

for (let [sym, { enter, leave }] of Object.entries(HOOKS)) {
    Interceptor.attach(Module.getExportByName(MODULE_NAME, sym), {
        onEnter: enter,
        onLeave: leave,
    })
}