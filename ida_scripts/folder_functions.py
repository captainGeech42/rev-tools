# ref: https://github.com/SentineLabs/AlphaGolang/blob/main/3.categorize_go_folders.py

import dataclasses

import FIDL.decompiler_utils as du

import idaapi
import ida_dirtree
import ida_funcs
import ida_name
import ida_xref

import idalib.log as liblog

DEBUG_MODE = False
LOG = liblog.Log("folder_functions", DEBUG_MODE)

# [func name, filepath arg idx]
FUNCS: list[tuple[str, int]] = [
    # ("z_schema_error", 0),
    # ("z_fatal_error", 1),
    ("z_get_basename", 0)
]

func_dir: ida_dirtree.dirtree_t = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)

@dataclasses.dataclass
class TreeNode:
    name: str
    funcs: set[int] = dataclasses.field(default_factory=set)

    nested_nodes: dict[str, "TreeNode"] = dataclasses.field(default_factory=dict)

    def dump(self, indent = 0):
        LOG.info(" "*indent + str(self))
        if DEBUG_MODE:
            for ea in self.funcs:
                LOG.info(" "*(indent+2) + f"* {ea:#x}")
        for _, n in self.nested_nodes.items():
            n.dump(indent+2)

    def commit(self, parent: str = ""):
        leaf = f"{parent}/{self.name}"
        if not func_dir.isdir(leaf):
            if r := func_dir.mkdir(leaf):
                LOG.error(f"failed to make dir '{leaf}': {func_dir.errstr(r)}")
                return
            
        for ea in self.funcs:
            n = ida_name.get_name(ea)
            func_dir.rename(n, f"{leaf}/{n}")
            pass
        
        for _, n in self.nested_nodes.items():
            n.commit(leaf)

    def __str__(self) -> str:
        return f"{self.name} - {len(self.funcs)} funcs, {len(self.nested_nodes)} nodes"
    
    def __repr__(self) -> str:
        return f"<TreeNode: {str(self)}>"

processed_func_eas: set[int] = set()
root_nodes: dict[str, TreeNode] = {}

def process_function(ea: int):
    for sym, argno in FUNCS:
        calls = du.find_all_calls_to_within(sym, ea)

        for c in calls:
            if len(c.args) <= argno:
                continue

            if c.args[argno].type != "string":
                continue

            path: str = c.args[argno].val
            if "/" not in path:
                # LOG.warning(f"found a plausible path in {ea:#x} but no /: {path}")
                continue

            n: TreeNode = None
            for part in path.split("/"):
                if not part:
                    continue

                if n is None:
                    if part not in root_nodes:
                        root_nodes[part] = TreeNode(part)
                    n = root_nodes[part]
                else:
                    if part not in n.nested_nodes:
                        n.nested_nodes[part] = TreeNode(part)
                    n = n.nested_nodes[part]
            
            n.funcs.add(ea)

def build_tree():
    for sym, _ in FUNCS:
        ea = ida_name.get_name_ea(idaapi.BADADDR, sym)

        # walk all xrefs to the function
        call_site = ida_xref.get_first_cref_to(ea)
        while call_site != idaapi.BADADDR:
            f: ida_funcs.func_t = ida_funcs.get_func(call_site)
            call_site = ida_xref.get_next_cref_to(ea, call_site)
            if not f:
                continue

            if f.start_ea in processed_func_eas:
                continue

            process_function(f.start_ea)
            processed_func_eas.add(f.start_ea)

def dump_tree():
    for _, node in root_nodes.items():
        node.dump()

def commit_tree():
    for _, node in root_nodes.items():
        node.commit()

# phase 1: walk all the calls and build a tree
LOG.info("building function tree")
build_tree()
LOG.info(f"processed {len(processed_func_eas)} functions into the tree")
dump_tree()

# phase 2: commit the tree into ida
commit_tree()
LOG.info(f"successfully committed function tree")