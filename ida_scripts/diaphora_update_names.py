# update the function names in a diaphora database
#   either the .sqlite for a single idb, or the diff export .diaphora

import enum
import sqlite3
from typing import Generator

import idautils
import ida_name

import idalib.log as liblog

DEBUG_MODE = False
LOG = liblog.Log("log_sym_namer", DEBUG_MODE)

# TARGET_DB = "/home/user/sec/vmware2025/ida/17.6.2/vmware-vmx.sqlite"
TARGET_DB = "/home/user/sec/vmware2025/ida/vmware-vmx_diff.diaphora"

class DiffTarget(enum.Enum):
    PRIMARY = "primary"
    SECONDARY = "secondary"

TARGET_TO_UPDATE = DiffTarget.PRIMARY

def func_genr() -> Generator[tuple[int, str], None, None]:
    """Generator for functions with non-default names"""

    for ea in idautils.Functions():
        ea: int

        name: str = ida_name.get_name(ea)
        if not name:
            LOG.warning(f"no name available for func @ {ea:#x}")
            continue
        
        if not name.startswith("sub_"):
            yield (ea, name)

def update_sqlite():
    """
    schema for this: https://github.com/joxeankoret/diaphora/blob/master/db_support/schema.py#L69

    $ sqlite3 vmware-vmx.sqlite
    SQLite version 3.49.1 2025-02-18 13:38:58
    Enter ".help" for usage hints.

    sqlite> select id,name,address from functions limit 10;
    1|.init_proc|1363968
    2|sub_14D020|1364000
    3|sub_152150|1384784
    4|sub_1522D2|1385170
    5|sub_1522EE|1385198
    6|sub_152400|1385472
    7|sub_1524B6|1385654
    8|sub_152F71|1388401
    9|sub_152FD9|1388505
    10|sub_153090|1388688
    """

    with sqlite3.connect(TARGET_DB) as con:
        cur = con.cursor()
        q = "UPDATE functions SET name = ? WHERE address = ?"
        cur.executemany(q, ((name, ea) for ea, name in func_genr()))
        con.commit()

def update_diaphora():
    """
    $ sqlite3 vmware-vmx_diff.diaphora 
    SQLite version 3.49.1 2025-02-18 13:38:58
    Enter ".help" for usage hints.
    sqlite> .schema
    CREATE TABLE config (main_db text, diff_db text, version text, date text);
    CREATE TABLE results (type, line, address, name, address2, name2,
                       ratio, nodes1, nodes2, description);
    CREATE UNIQUE INDEX uq_results on results(address, address2);
    CREATE TABLE unmatched (type, line, address, name);

    sqlite> select * from results limit 5;
    best|00000|00152400|sub_152400|00152400|sub_152400|1.0000000|18|18|100% equal
    best|00001|001524b6|sub_1524B6|001524b6|sub_1524B6|1.0000000|1|1|100% equal
    best|00002|001540a0|sub_1540A0|001540a0|sub_1540A0|1.0000000|2|2|100% equal
    best|00003|001543a4|start|001543a4|start|1.0000000|1|1|100% equal
    best|00004|00154500|sub_154500|00154500|sub_154500|1.0000000|4|4|100% equal
               ^^^^^^^^^^^^^^^^^^^
               primary
                                   ^^^^^^^^^^^^^^^^^^^
                                   secondary

    sqlite> select * from unmatched limit 5;
    primary|00000|0014d020|sub_14D020
    primary|00001|00155100|sub_155100
    primary|00002|001679a0|sub_1679A0
    primary|00003|00167bf0|sub_167BF0
    primary|00004|00168f00|sub_168F00
    """
    
    with sqlite3.connect(TARGET_DB) as con:
        cur = con.cursor()

        cols = {
            DiffTarget.PRIMARY: ["name", "address"],
            DiffTarget.SECONDARY: ["name2", "address2"],
        }
        q = f"UPDATE results SET {cols[TARGET_TO_UPDATE][0]} = ? WHERE {cols[TARGET_TO_UPDATE][1]} = ?"
        cur.executemany(q, ((name, f"{ea:08x}") for ea, name in func_genr()))
        con.commit()

        q = "UPDATE unmatched SET name = ? WHERE address = ? AND type = ?"
        cur.executemany(q, ((name, f"{ea:08x}", TARGET_TO_UPDATE.value) for ea, name in func_genr()))
        con.commit()

def main():
    LOG.info(f"updating {TARGET_DB} as the {TARGET_TO_UPDATE} diff target")

    if TARGET_DB.endswith(".sqlite"):
        update_sqlite()
    elif TARGET_DB.endswith(".diaphora"):
        update_diaphora()
    else:
        LOG.error("don't know how to handle this file")

    LOG.success("done!")

main()