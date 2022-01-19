.PHONY: all clean

SOURCE = $(wildcard */*.cpp)
ASM_SOURCE = $(patsubst %.cpp, %.orig.s, $(SOURCE))

GCC_REQUIRED=8
GCC_MAJOR = $(shell echo __GNUC__ | $(CXX) -E -x c - | tail -n 1)
GCC_MAJOR_GTE8 = $(shell expr $(GCC_MAJOR) \>= $(GCC_REQUIRED))

COMPILE_COMMAND = 
TEST_COMMAND = 

ifeq ($(GCC_MAJOR_GTE8), 1)
	COMPILE_COMMAND = $(CXX) $^ -S -O2 -std=c++17 -o $@
endif

all: test

test: $(ASM_SOURCE)
	./run_gcc_ge8_gensrc_test.sh $(GCC_MAJOR) $(GCC_REQUIRED)

clean:
	rm -f $(shell find ./ -name *.s)

%.orig.s: %.cpp
	$(COMPILE_COMMAND)