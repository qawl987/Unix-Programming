PROGS = libzpoline.so

CC = gcc

CLEANFILES = $(PROGS) *.o *.d

SRCDIR ?= ./

OUTPUT_FOLDER = build-file/
# CFLAGS = -O3 -pipe
# CFLAGS += -g -rdynamic
# CFLAGS += -Werror -Wall -Wunused-function
# CFLAGS += -Wextra
CFLAGS += -shared -fPIC
# CFLAGS += -DSUPPLEMENTAL__REWRITTEN_ADDR_CHECK

# LD_VERSION = $(shell ld --version | head -1 | grep -oP '[\d\.]+' | sed 's/\.//' | sed 's/\..*//' | head -1 )
# # differentiate the code according to the library version
# ifeq ($(shell test $(LD_VERSION) -ge 239; echo $$?),0)
#   CFLAGS += -DDIS_ASM_VER_239
# else ifeq ($(shell test $(LD_VERSION) -ge 229; echo $$?),0)
#   CFLAGS += -DDIS_ASM_VER_229
# endif

LDFLAGS += -lcapstone

C_SRCS = main.c

EX1_SRCS = ex1.c
EX1OBJS = $(EX1_SRCS:.c=.o)
EX2_SRCS = ex2.c
EX2OBJS = $(EX2_SRCS:.c=.o)
ORIGIN_SRCS = origin.c
ORIGINOBJS = $(ORIGIN_SRCS:.c=.o)
.PHONY: all
all: $(PROGS)

ex1: $(EX1OBJS)
	$(CC) $(CFLAGS) -o $(OUTPUT_FOLDER)libzpoline.so.1 $^ $(LDFLAGS)

ex2: $(EX2OBJS)
	$(CC) $(CFLAGS) -o $(OUTPUT_FOLDER)libzpoline.so.2 $^ $(LDFLAGS)

origin: $(ORIGINOBJS)
	$(CC) $(CFLAGS) -o $(OUTPUT_FOLDER)libzpoline.so.origin $^ $(LDFLAGS)

libzpoline.so: ex3.o
	$(CC) $(CFLAGS) -o $(OUTPUT_FOLDER)$@ $^ $(LDFLAGS)

hook-lib.so: hook-lib.o
	$(CC) $(CFLAGS) -o $(OUTPUT_FOLDER)$@ $^ $(LDFLAGS)

logger.so: logger.o
	$(CC) $(CFLAGS) -o $(OUTPUT_FOLDER)$@ $^ $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)
	-@rm -rf build-file/*

### test case #######

test_ex1:
	LD_PRELOAD=./build-file/libzpoline.so.1 ./ex1

test_ex2_1:
	LD_PRELOAD=./build-file/libzpoline.so.2 /usr/bin/echo 'uphw{7h15_15_4_51mpl3_fl46_fr0m_200l4b}'

test_ex2_2:
	LD_PRELOAD=./build-file/libzpoline.so.2 cat ex2-2.txt

test_ex3:
	LD_PRELOAD=./build-file/libzpoline.so LIBZPHOOK=./libex3hook.so ./ex3

test_ex4_1:
	LD_PRELOAD=./build-file/libzpoline.so LIBZPHOOK=./logger.so touch t.c

test_ex4_2:
	LD_PRELOAD=./build-file/libzpoline.so LIBZPHOOK=./logger.so cat /etc/hosts

test_ex5:
	LD_PRELOAD=./build-file/libzpoline.so LIBZPHOOK=./logger.so wget http://www.google.com -q -t 1

test_ex6:
	LD_PRELOAD=./build-file/libzpoline.so LIBZPHOOK=./logger.so python3 -c 'import os; os.system("wget http://www.google.com -q -t 1")'
