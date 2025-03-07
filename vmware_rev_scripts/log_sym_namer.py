import FIDL.decompiler_utils as du

import idaapi
import ida_funcs
import ida_name
import ida_xref

import idalib.log

LOG = idalib.log.Log("log_sym_namer")

LOG_SYMBOL = "z_idk_logging_1"

# phase 1: get the function eas that call the log func

targ_ea = ida_name.get_name_ea(idaapi.BADADDR, LOG_SYMBOL)
LOG.info(f"analyzing calls to {targ_ea:#x}")

func_eas: set[int] = set()
failed_eas: set[int] = set()

call_site = ida_xref.get_first_cref_to(targ_ea)
while call_site != idaapi.BADADDR:
    f = ida_funcs.get_func(call_site)
    if f:
        n = ida_name.get_name(f.start_ea)
        if n.startswith("sub_"):
            func_eas.add(f.start_ea)
    else:
        # LOG.warning(f"no function info for call @ {call_site:#x}")
        failed_eas.add(call_site)

    call_site = ida_xref.get_next_cref_to(targ_ea, call_site)

LOG.info(f"found {len(func_eas)} unnamed functions that call {LOG_SYMBOL}")
LOG.info(f"also skipping {len(failed_eas)} call sites that aren't in a function")

# phase 2: get the calls to the logger in each func

num_set = 0

for func_ea in func_eas:
    calls = du.find_all_calls_to_within(LOG_SYMBOL, func_ea)

    candidate_name = ""

    for c in calls:
        if len(c.args) < 2:
            continue

        if not (c.args[0].type == "string" and c.args[1].type == "string"):
            continue

        fstr = c.args[0].val
        if fstr.startswith("%s: "):
            n = c.args[1].val

            # if we got a name, see if it is the same as the one we had previously
            # if we didnt previously have one, save it
            if candidate_name:
                if n != candidate_name:
                    # got a diff name, clear it out and stop processing
                    candidate_name = ""
                    break
            else:
                candidate_name = n
    
    if candidate_name:
        candidate_name = "aut_" + candidate_name

        ctr = 0
        n = candidate_name
        while ida_name.get_name_ea(idaapi.BADADDR, n) != idaapi.BADADDR:
            # we already have a func with this name
            # add a counter
            ctr += 1
            n = f"{candidate_name}_{ctr}"
        
        if ida_name.set_name(func_ea, n):
            LOG.info(f"renamed {func_ea:#x} to {n}")
            num_set +=1
        else:
            LOG.error(f"failed to rename {func_ea:#x} to {n}")

LOG.info(f"renamed {num_set} functions")