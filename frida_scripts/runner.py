import argparse
import logging
import sys
import time

import frida

# replaced by build action defined in the Makefile
# extraneous whitespace breaks the packed module parsing in frida
SCRIPT_CODE = """
XXXXX_SCRIPT_HERE_XXXXX
""".strip()

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOG = logging.getLogger("runner")

def on_message(message, data):
    print(message)

def attach(proc: str):
    LOG.info("attaching to %s", proc)

    try:
        # convert to int if it can so that frida tries it as a pid, not a process name
        proc = int(proc)
    except ValueError:
        pass

    session = frida.attach(proc)
    script = session.create_script(SCRIPT_CODE)
    script.on("message", on_message)
    script.load()

def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="runner", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("-p", "--process", required=True, help="target PID or process name to attach to")

    return parser.parse_args(argv)

def main(argv: list[str]) -> int:
    args = parse_args(argv)

    attach(args.process)

    while True:
        time.sleep(1)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))