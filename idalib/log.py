"""
Simple logging library for IDAPython
"""

import traceback

import ida_kernwin

class Log:
    def __init__(self, progname: str):
        self._progname = progname

        if not ida_kernwin.is_msg_inited():
            raise Exception("msg not ready yet, can't init logging")
    
    def _write_msg(self, level: str, msg: str, *args):
        out = f"[{self._progname}][{level}] " + (str(msg) % args) + "\n"
        ida_kernwin.msg(out)

    def info(self, msg: str, *args):
        self._write_msg("*", msg, *args)

    def success(self, msg: str, *args):
        self._write_msg("+", msg, *args)

    def warning(self, msg: str, *args):
        self._write_msg("-", msg, *args)

    def error(self, msg: str, *args):
        self._write_msg("!", msg, *args)

    def exc(self, msg: str, *args):
        self._write_msg("!", msg, *args)
        ida_kernwin.msg(traceback.format_exc())
