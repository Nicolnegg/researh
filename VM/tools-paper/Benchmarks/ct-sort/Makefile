CFLAGS=-m32 -march=i386
LIBSYM_DIR=../../__libsym__
LIBSYM_A=$(LIBSYM_DIR)/libsym.a
ifeq ($(wildcard $(LIBSYM_A)),)
LIB=
else
LIB=-L$(LIBSYM_DIR)/ -lsym
endif
LOG="./log"
GCC5 ?= $(shell command -v gcc-5 >/dev/null 2>&1 && echo gcc-5 || echo gcc)
GCC8 ?= $(shell command -v gcc-8 >/dev/null 2>&1 && echo gcc-8 || echo gcc)
CL30 ?= $(shell command -v clang-3.0 >/dev/null 2>&1 && echo clang-3.0 || echo clang)
CL39 ?= $(shell command -v clang-3.9 >/dev/null 2>&1 && echo clang-3.9 || echo clang)
CL7  ?= $(shell command -v clang-7 >/dev/null 2>&1 && echo clang-7 || echo clang)

.PHONY: all build sort sort_multiplex sort_negative sort_legacy sort_multiplex_legacy sort_negative_legacy legacy-all legacy-analysis clean mrproper
all: build
build: sort sort_multiplex sort_negative

define compile
	echo "-------------------"
	echo " Compiling $(1)"
	echo "-------------------"
	$(GCC5) -fno-stack-protector $(CFLAGS) -O0 lib.c $(1).c -o $(1)_gcc5_O0 $(LIB)
	$(GCC5) -fno-stack-protector $(CFLAGS) -O3 lib.c $(1).c -o $(1)_gcc5_O3 $(LIB)
	$(GCC8) -fno-stack-protector $(CFLAGS) -O0 lib.c $(1).c -o $(1)_gcc8_O0 $(LIB)
	$(GCC8) -fno-stack-protector $(CFLAGS) -O3 lib.c $(1).c -o $(1)_gcc8_O3 $(LIB)
	$(CL39) $(CFLAGS) -O0 lib.c $(1).c -o $(1)_cl39_O0 $(LIB)
	$(CL39) $(CFLAGS) -O3 lib.c $(1).c -o $(1)_cl39_O3 $(LIB)
	$(CL30) $(CFLAGS) -O0 lib.c $(1).c -o $(1)_cl30_O0 $(LIB)
	$(CL30) $(CFLAGS) -O3 lib.c $(1).c -o $(1)_cl30_O3 $(LIB)
	$(CL7) $(CFLAGS) -O0 lib.c $(1).c -o $(1)_cl7_O0 $(LIB)
	$(CL7) $(CFLAGS) -O3 lib.c $(1).c -o $(1)_cl7_O3 $(LIB)
endef

define test
	@echo -n "$(1): "
	@mkdir -p $(LOG)
	@mkdir -p /tmp/SMTDIR/trace/; rm -R /tmp/SMTDIR/; mkdir -p /tmp/SMTDIR/trace/
	$(eval PARAMS := -relse -relse-dedup 1 -relse-fp instr \
	-fml-solver-timeout 0 -relse-timeout 3600 -sse-depth 10000 \
	-relse-paths 50 -sse-memory memory.txt -sse-load-ro-sections \
	-sse-load-sections .got.plt,.data,.plt -fml-solver boolector \
	-relse-store-type sha -relse-memory-type row-map 	\
	-sse-address-trace-file /tmp/SMTDIR/trace/ -sse-smt-dir \
	/tmp/SMTDIR/ -sse-comment  -relse-print-model \
	$(1))
	@echo "binsec $(PARAMS)" > $(LOG)/$(1)
	binsec $(PARAMS) >> $(LOG)/$(1) 2>&1 && \
	([ $$? -eq 0 ] && echo "PASS") || echo "FAIL!"
endef

define full_test
	@echo "-------------------"
	@echo " Testing $(1)"
	@echo "-------------------"
	$(call test,$(1)_"gcc5_O0")
	$(call test,$(1)_"gcc5_O3")
	$(call test,$(1)_"gcc8_O0")
	$(call test,$(1)_"gcc8_O3")
	$(call test,$(1)_"cl30_O0")
	$(call test,$(1)_"cl30_O3")
	$(call test,$(1)_"cl39_O0")
	$(call test,$(1)_"cl39_O3")
	$(call test,$(1)_"cl7_O0")
	$(call test,$(1)_"cl7_O3")
endef

sort:
	@$(call compile,$@)

sort_multiplex:
	@$(call compile,$@)


sort_negative:
	@$(call compile,$@)

sort_legacy:
	@$(call compile,sort)
	@$(call full_test,sort)

sort_multiplex_legacy:
	@$(call compile,sort_multiplex)
	@$(call full_test,sort_multiplex)

sort_negative_legacy:
	@$(call compile,sort_negative)
	@$(call full_test,sort_negative)

legacy-all: sort_legacy sort_multiplex_legacy sort_negative_legacy

legacy-analysis:
	@$(call full_test,sort)
	@$(call full_test,sort_multiplex)
	@$(call full_test,sort_negative)

clean:
	rm -rf *.o *.csv *.out

mrproper: clean
	find . -type f -executable | xargs rm
