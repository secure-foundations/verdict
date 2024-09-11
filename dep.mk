##########################################################################
### Makefile to compile Verus project with external cargo dependencies ###
##########################################################################

# Uses these variables (for example):
#   TARGET = Target executable name (e.g. vpl)
#   SOURCE = All source files used for monitoring changes (e.g. $(wildcard src/*.rs) $(wildcard src/*.pl))
#   MAIN = Main file passed to Verus (e.g. src/main.rs)
#   CARGO_DEPS = Rust dependencies added with `cargo add` (e.g. peg clap thiserror tempfile)
#   VERUS_DEPS = Verus dependency paths (e.g. vest). For each dep in VERUS_DEPS, we expect $(dep).rlib and $(dep).verusdata to exist

# If $(TARGET) ends in rlib, pass some additional flags to Verus
ifeq ($(suffix $(TARGET)),.rlib)
	LIB_FLAGS = --crate-type=lib
else
	LIB_FLAGS =
endif

.PHONY: debug
debug: target/debug/$(TARGET)

.PHONY: release
release: target/release/$(TARGET)

target/%/$(TARGET): \
	$(foreach dep,$(CARGO_DEPS),target/%/lib$(dep).rlib) \
	$(SOURCE)

	mkdir -p target/$*

# Check if each dependency in VERUS_DEPS exists
	@for dep in $(VERUS_DEPS); do \
		rlib=../$$dep/target/$*/lib$$dep.rlib; \
		if [ ! -f $$rlib ] || [ ! -f $$rlib.verusdata ]; then \
			echo "Cannot find external Verus library $$rlib (or $$rlib.verusdata)"; \
			exit 1; \
		fi \
    done

# Each dependency <dep> in CARGO_DEPS is mapped to verus argument --extern <dep>=target/<release/debug>/deps/lib<dep>-*.rlib
# Each dependency <dep> in VERUS_DEPS is mapped to verus argument
#     --extern <dep>=../<dep>/target/<release/debug>/lib<dep>.rlib
#     --import <dep>=../<dep>/target/<release/debug>/lib<dep>.rlib.verusdata
	verus $(MAIN) \
		$(LIB_FLAGS) \
		-L dependency=target/$*/deps \
		$(foreach dep,$(CARGO_DEPS),--extern $(dep)=$(firstword $(wildcard target/$*/deps/lib$(dep)-*.rlib))) \
		$(foreach dep,$(VERUS_DEPS),--extern $(dep)=../$(dep)/target/$*/lib$(dep).rlib --import $(dep)=../$(dep)/target/$*/lib$(dep).rlib.verusdata) \
		--compile \
		$(if $(filter release,$*),-C opt-level=3) \
		-o target/$*/$(TARGET) \
		--export target/$*/$(TARGET).verusdata

target/debug/lib%.rlib: Cargo.toml
	cargo build --package=$*

target/release/lib%.rlib: Cargo.toml
	cargo build --package=$* --release

.PHONY: clean
clean:
	cargo clean
