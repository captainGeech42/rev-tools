# enrich a stripped stack trace with IDA symbols

STACK_TRACE = """
pwndbg> k
#0  0x00005a4579b2d150 in ?? ()
#1  0x00005a4579b5dc08 in ?? ()
#2  0x00005a4579a90df1 in ?? ()
#3  0x00005a4579a91cb0 in ?? ()
#4  0x00005a4579a9705c in ?? ()
#5  0x00005a4579a8ac67 in ?? ()
#6  0x000078e71622a1ca in __libc_start_call_main (main=main@entry=0x5a4579a8a0a0, argc=argc@entry=8, argv=argv@entry=0x7fff463f07b8) at ../sysdeps/nptl/libc_start_call_main.h:58
#7  0x000078e71622a28b in __libc_start_main_impl (main=0x5a4579a8a0a0, argc=8, argv=0x7fff463f07b8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fff463f07a8) at ../csu/libc-start.c:360
"""

VMMAP = """
pwndbg> vmmap vmware-vmx
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File
►   0x5a4579937000     0x5a4579a84000 r--p   14d000      0 /usr/lib/vmware/bin/vmware-vmx
►   0x5a4579a84000     0x5a457a619000 r-xp   b95000 14d000 /usr/lib/vmware/bin/vmware-vmx
►   0x5a457a619000     0x5a457aaeb000 r--p   4d2000 ce2000 /usr/lib/vmware/bin/vmware-vmx
►   0x5a457aaec000     0x5a457abf7000 r--p   10b000 11b4000 /usr/lib/vmware/bin/vmware-vmx
►   0x5a457abf7000     0x5a457ac4f000 rw-p    58000 12bf000 /usr/lib/vmware/bin/vmware-vmx
    0x5a457ac4f000     0x5a457ad85000 rw-p   136000      0 [anon_5a457ac4f]
"""

############################################################

import re

import ida_funcs
import ida_name

STACK_TRACE_ADDR_PAT = re.compile(r"#\d+\s*(?P<addr>0x[0-9a-f]{16})")

VMMAP_ADDR_PAT = re.compile(r"(?P<addr>0x[0-9a-f]{7,16})")

def get_target_range() -> tuple[int, int]:
    """Parse out the VA range from the vmmap"""

    min_va = 0xffffffff_ffffffff
    max_va = 0

    for va_s in VMMAP_ADDR_PAT.findall(VMMAP):
        va = int(va_s, 16)

        if va < min_va:
            min_va = va
        if va > max_va:
            max_va = va
    
    return (min_va, max_va)

def get_stack_addrs(min_va: int, max_va: int) -> list[int]:
    """Get a list in order of the stack trace addrs in scope"""

    out: list[int] = []
    
    for va_s in STACK_TRACE_ADDR_PAT.findall(STACK_TRACE):
        va = int(va_s, 16)

        if min_va <= va < max_va:
            out.append(va)
    
    return out

def enrich_addr(va: int) -> str:

    f: ida_funcs.func_t = ida_funcs.get_func(va)
    if not f:
        return "<unknown>"
    
    n = ida_name.get_name(f.start_ea)

    offset = va - f.start_ea

    return f"{n}+{offset:#x}"

def main():
    min_va, max_va = get_target_range()

    addrs = get_stack_addrs(min_va, max_va)

    print("enriched stack trace:")
    for i, va in enumerate(addrs):
        base_va = va - min_va
        print(f"#{i}  {base_va:#x} - {enrich_addr(base_va)}")

main()