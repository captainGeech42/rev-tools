"""
Simple logging library for IDAPython
"""

import traceback

import ida_kernwin

class Log:
    def __init__(self, progname: str, debug = False):
        self._progname = progname
        self._debug = debug

        if not ida_kernwin.is_msg_inited():
            raise Exception("msg not ready yet, can't init logging")
    
    def _write_msg(self, level: str, msg: str):
        try:
            out = f"[{self._progname}][{level}] {msg}\n"
            ida_kernwin.msg(out)
        except TypeError:
            ida_kernwin.msg("LOG FAILURE")
            ida_kernwin.msg(msg)

    def debug(self, msg: str):
        if self._debug:
            self._write_msg("#", msg)

    def info(self, msg: str):
        self._write_msg("*", msg)

    def success(self, msg: str):
        self._write_msg("+", msg)

    def warning(self, msg: str):
        self._write_msg("-", msg)

    def error(self, msg: str):
        self._write_msg("!", msg)

    def exc(self, msg: str):
        self._write_msg("!", msg)
        ida_kernwin.msg(traceback.format_exc())
