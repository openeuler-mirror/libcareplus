MAKEFLAGS += --no-builtin-rules

SUBDIRS := $(patsubst %/desc,%,$(wildcard */desc))

AARCH64_NO_SUPPORT_TESTS = fail_coro fail_coro_listed
ARCH = $(shell uname -m)
ifeq ($(ARCH), aarch64)
	SUBDIRS := $(filter-out $(AARCH64_NO_SUPPORT_TESTS), $(SUBDIRS))
endif
ifeq ($(ARCH), riscv64)
	SUBDIRS := $(filter-out $(AARCH64_NO_SUPPORT_TESTS), $(SUBDIRS))
endif
ifeq ($(ARCH), loongarch64)
	SUBDIRS := $(filter-out $(AARCH64_NO_SUPPORT_TESTS), $(SUBDIRS))
endif
GCC_GE8_GENSRC_TESTS := $(patsubst gcc_ge8_gensrc/%/sub_desc,%,$(wildcard gcc_ge8_gensrc/*/sub_desc))

KPATCH_PATH:=$(CURDIR)/../src
export KPATCH_PATH

all: run

list:
	@echo TESTS: $(SUBDIRS) $(GCC_GE8_GENSRC_TESTS)

fastsleep.so: CFLAGS += -fPIC
fastsleep.so: fastsleep.c
	$(LINK.c) $^ -o $@ -shared -ldl

clean: $(addprefix clean-,$(SUBDIRS))
	rm -fr 	$(CURDIR)/build-patchroot	\
		$(CURDIR)/lpmake-patchroot	\
		$(CURDIR)/lpmakelevel-patchroot
	rm -f fastsleep.so
	make -C execve clean
	make -C gcc_ge8_gensrc clean

clean-%: FORCE
	make -C $* clean

build: $(addprefix build-,$(SUBDIRS))

build-%: FORCE
	make -C $* clean all install DESTDIR=build

build-patchroot: build
	mkdir -p $(CURDIR)/build-patchroot
	find	-type l -iname \*.kpatch \
		-exec cp -L \{} $(CURDIR)/build-patchroot \;

LPMAKE_TGTS := $(addprefix lpmake-,$(SUBDIRS))
lpmake: $(LPMAKE_TGTS)
lpmakelevel: $(LPMAKE_TGTS)

lpmake-%: export LPMAKE_PATCHROOT := lpmake
lpmake-%: FORCE
	cd $*; $(CURDIR)/../src/libcare-patch-make --clean *.diff -i 0001

lpmake-patchroot: lpmake
	mkdir -p $(CURDIR)/lpmake-patchroot
	find 	-path '*/lpmake/*.kpatch' \
		-exec cp \{} $(CURDIR)/lpmake-patchroot \;

lpmakelevel-patchroot: lpmake
	mkdir -p $(CURDIR)/lpmakelevel-patchroot
	for f in $$(find -path '*/lpmake/*.kpatch'); do			\
		buildid=$${f%.kpatch};					\
		buildid=$${buildid##*/};				\
		dir=$(CURDIR)/lpmakelevel-patchroot/$$buildid/;	\
		mkdir -p $$dir/1/;					\
		cp $$f $$dir/1/kpatch.bin;				\
		ln -fs 1 $$dir/latest;					\
	done

RUN_TESTS = ./run_tests.sh $(RUNTESTSFLAGS)

run-file-%: %
	$(RUN_TESTS)

run-unpatch:
	$(RUN_TESTS) -f test_unpatch_files

run-dir-%: %
	$(RUN_TESTS) -f test_patch_dir

run-startup-%: % %-patchroot
	$(RUN_TESTS) -f test_patch_startup

run-startup-ld-linux-%: % %-patchroot
	$(RUN_TESTS) -f test_patch_startup_ld_linux

run-patchlevel: fastsleep.so
run-patchlevel: build-patchlevel
	$(RUN_TESTS) -f test_patch_patchlevel

run-build: fastsleep.so
run-build: run-file-build run-dir-build run-startup-build run-unpatch
run-build: run-startup-ld-linux-build

run-lpmake: RUNTESTSFLAGS := -d lpmake
run-lpmake: fastsleep.so
run-lpmake: run-dir-lpmake run-startup-lpmake
run-lpmake: run-startup-ld-linux-lpmake

run-lpmakelevel: RUNTESTSFLAGS := -d lpmake -p $(CURDIR)/lpmakelevel-patchroot
run-lpmakelevel: fastsleep.so
run-lpmakelevel: run-startup-lpmakelevel

run-gcc_ge8_gensrc:
	make -C gcc_ge8_gensrc

run: run-build run-patchlevel run-gcc_ge8_gensrc # run-lpmake run-lpmakelevel

FORCE:
