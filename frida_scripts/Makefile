INPUT_SCRIPTS=${wildcard *.ts}
RUNNER_SCRIPTS=$(patsubst %.ts,build/%.py,$(INPUT_SCRIPTS))

.PHONY: all
all: $(RUNNER_SCRIPTS)

# sed ref: https://unix.stackexchange.com/a/450857

build/%.py: %.ts runner.py
	@mkdir -p build

	frida-compile $< -c | sed -e '/^XXXXX_SCRIPT_HERE_XXXXX/{r /dev/stdin' -e 'd;}' runner.py > $@

.PHONY: clean
clean:
	rm -rf build
