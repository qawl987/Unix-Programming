# Makefile for Gotoku

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -g # General compiler flags (warnings, debug info, optimization)
SOFLAGS = -shared -fPIC       # Flags for building shared objects
LDFLAGS = -L. -lgotoku -Wl,-rpath=. -ldl # Linker flags: search libs in ., link gotoku, set runtime path, link dynamic loader lib

# Targets
TARGET_SO = libgotoku.so
TARGET_EXE = gotoku.local

# Source files
SRC_SO = libgotoku_dummy.c
SRC_EXE = gotoku.c
# gops.c is included by gotoku.c, not compiled separately

# Default target: build everything
all: clean $(TARGET_EXE)

# Rule to build the shared library
# Depends on its source file (and implicitly any headers it includes)
$(TARGET_SO): $(SRC_SO)
	$(CC) $(CFLAGS) $(SOFLAGS) -o $@ $<

# Rule to build the executable
# Depends on its source file AND the shared library it links against
# (and implicitly any headers/included files like gops.c)
$(TARGET_EXE): $(SRC_EXE) $(TARGET_SO)
	$(CC) $(CFLAGS) -o $@ $(SRC_EXE) $(LDFLAGS)

# Rule to clean up generated files
clean:
	rm -f $(TARGET_EXE) $(TARGET_SO) *.o core.*

# Phony targets (targets that don't represent files)
.PHONY: all clean

inject:
	gcc -o inject.so -shared -g -fPIC inject.c -ldl

local:
	LD_PRELOAD=./inject.so ./gotoku.local

debug:
	LD_PRELOAD=./inject.so gdb --args ./gotoku.local