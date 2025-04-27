/*
 *
 * Copyright 2021 Kenichi Yasukata
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#define PACKAGE "1"
#define PACKAGE_VERSION "1"
#define SYSCALL_WRITE_ID 0x01
// #define SUPPLEMENTAL__REWRITTEN_ADDR_CHECK 1
#include <dis-asm.h>
#include <sched.h>
#include <dlfcn.h>
#include <unistd.h>

extern void syscall_addr(void);
extern long enter_syscall(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);
extern void asm_syscall_hook(void);

void ____asm_impl(void)
{
	/*
	 * enter_syscall triggers a kernel-space system call
	 */
	// hook_fn(rax_on_stack, rdi, rsi, rdx, r10_on_stack, r8, r9);
	//         rdi         , rsi, rdx, rcx, r8         , r9
	// User:   %rdi, %rsi, %rdx, %rcx, %r8, %r9
	// Kernel: %rdi, %rsi, %rdx, %r10, %r8, %r9
	asm volatile(
		".globl enter_syscall \n\t"
		"enter_syscall: \n\t"
		"movq 8(%rsp),%rax \n\t"
		"mov %rcx, %r10 \n\t"
		".globl syscall_addr \n\t"
		"syscall_addr: \n\t"
		"syscall \n\t"
		"ret \n\t");

	asm volatile(
		".globl asm_syscall_hook \n\t"
		"asm_syscall_hook: \n\t"

		"cmpq $15, %rax \n\t" // rt_sigreturn
		"je do_rt_sigreturn \n\t"
		"pushq %rbp \n\t"
		"movq %rsp, %rbp \n\t"

		/*
		 * NOTE: for xmm register operations such as movaps
		 * stack is expected to be aligned to a 16 byte boundary.
		 */

		"andq $-16, %rsp \n\t" // 16 byte stack alignment

		/* assuming callee preserves r12-r15 and rbx  */

		"pushq %r11 \n\t"
		"pushq %r9 \n\t"
		"pushq %r8 \n\t"
		"pushq %rdi \n\t"
		"pushq %rsi \n\t"
		"pushq %rdx \n\t"
		"pushq %rcx \n\t"

		/* arguments for syscall_hook */

		"pushq 8(%rbp) \n\t" // return address
		"pushq %rax \n\t"
		"pushq %r10 \n\t"

		/* up to here, stack has to be 16 byte aligned */

		"callq syscall_hook@plt \n\t"

		"popq %r10 \n\t"
		"addq $16, %rsp \n\t" // discard arg7 and arg8

		"popq %rcx \n\t"
		"popq %rdx \n\t"
		"popq %rsi \n\t"
		"popq %rdi \n\t"
		"popq %r8 \n\t"
		"popq %r9 \n\t"
		"popq %r11 \n\t"

		"leaveq \n\t"

		"retq \n\t"

		"do_rt_sigreturn:"
		"addq $8, %rsp \n\t"
		"jmp syscall_addr \n\t");
}

static long (*hook_fn)(int64_t a1, int64_t a2, int64_t a3,
					   int64_t a4, int64_t a5, int64_t a6,
					   int64_t a7) = enter_syscall;

long syscall_hook(int64_t rdi, int64_t rsi,
				  int64_t rdx, int64_t __rcx __attribute__((unused)),
				  int64_t r8, int64_t r9,
				  int64_t r10_on_stack /* 4th arg for syscall */,
				  int64_t rax_on_stack,
				  int64_t retptr __attribute__((unused)))
{
	char *buf = NULL;
	if (rax_on_stack == SYSCALL_WRITE_ID && rdi == STDOUT_FILENO)
	{
		const char *ptr = (const char *)rsi;
		size_t length = (size_t)rdx;
		buf = malloc(length);
		static const char leet_to_char[] = "oizeasgt";
		ssize_t num_leets = strlen(leet_to_char);

		for (size_t i = 0; i < length; i++)
		{
			ssize_t leet = ptr[i] - '0';
			if (0 <= leet && leet < num_leets)
			{
				buf[i] = leet_to_char[leet];
			}
			else
			{
				buf[i] = ptr[i];
			}
		}
		rsi = (int64_t)buf;
	}
	int64_t ret = hook_fn(rdi, rsi, rdx, r10_on_stack, r8, r9, rax_on_stack);
	free(buf);
	return ret;
}

struct disassembly_state
{
	char *code;
	size_t off;
};

static int do_rewrite(void *data, enum disassembler_style style ATTRIBUTE_UNUSED, const char *fmt, ...)
{
	struct disassembly_state *s = (struct disassembly_state *)data;
	char buf[4096];
	va_list arg;
	va_start(arg, fmt);
	vsprintf(buf, fmt, arg);

	if (strstr(buf, "(%rsp)") && !strncmp(buf, "-", 1))
	{
		int32_t off;
		sscanf(buf, "%x(%%rsp)", &off);
		if (-0x78 > off && off >= -0x80)
		{
			printf("\x1b[41mthis cannot be handled: %s\x1b[39m\n", buf);
			assert(0);
		}
		else if (off < -0x80)
		{
			/* this is skipped */
		}
		else
		{
			off &= 0xff;
			{
				uint8_t *ptr = (uint8_t *)(((uintptr_t)s->code) + s->off);
				{
					int i;
					for (i = 0; i < 16; i++)
					{
						if (ptr[i] == 0x24 && ptr[i + 1] == off)
						{
							ptr[i + 1] -= 8;
							break;
						}
					}
				}
			}
		}
	}
	else
		/* replace syscall and sysenter with callq *%rax */
		if (!strncmp(buf, "syscall", 7) || !strncmp(buf, "sysenter", 8))
		{
			uint8_t *ptr = (uint8_t *)(((uintptr_t)s->code) + s->off);
			if ((uintptr_t)ptr == (uintptr_t)syscall_addr)
			{
				/*
				 * skip the syscall replacement for
				 * our system call hook (enter_syscall)
				 * so that it can issue system calls.
				 */
				goto skip;
			}
			ptr[0] = 0xff; // callq
			ptr[1] = 0xd0; // *%rax
		}
skip:
	va_end(arg);
	return 0;
}

/* find syscall and sysenter using the disassembler, and rewrite them */
static void disassemble_and_rewrite(char *code, size_t code_size, int mem_prot)
{
	struct disassembly_state s = {0};
	/* add PROT_WRITE to rewrite the code */
	assert(!mprotect(code, code_size, PROT_WRITE | PROT_READ | PROT_EXEC));
	disassemble_info disasm_info = {0};
	init_disassemble_info(&disasm_info, &s, (fprintf_ftype)printf, do_rewrite);
	disasm_info.arch = bfd_arch_i386;
	disasm_info.mach = bfd_mach_x86_64;
	disasm_info.buffer = (bfd_byte *)code;
	disasm_info.buffer_length = code_size;
	disassemble_init_for_target(&disasm_info);
	disassembler_ftype disasm;
	disasm = disassembler(bfd_arch_i386, false, bfd_mach_x86_64, NULL);
	s.code = code;
	while (s.off < code_size)
		s.off += disasm(s.off, &disasm_info);
	/* restore the memory protection */
	assert(!mprotect(code, code_size, mem_prot));
}

/* entry point for binary rewriting */
static void rewrite_code(void)
{
	FILE *fp;
	/* get memory mapping information from procfs */
	assert((fp = fopen("/proc/self/maps", "r")) != NULL);
	{
		char buf[4096];
		while (fgets(buf, sizeof(buf), fp) != NULL)
		{
			/* we do not touch stack and vsyscall memory */
			if (((strstr(buf, "[stack]\n") == NULL) && (strstr(buf, "[vsyscall]\n") == NULL) && (strstr(buf, "[vdso]\n") == NULL)))
			{
				int i = 0;
				char addr[65] = {0};
				char *c = strtok(buf, " ");
				while (c != NULL)
				{
					switch (i)
					{
					case 0:
						strncpy(addr, c, sizeof(addr) - 1);
						break;
					case 1:
					{
						int mem_prot = 0;
						{
							size_t j;
							for (j = 0; j < strlen(c); j++)
							{
								if (c[j] == 'r')
									mem_prot |= PROT_READ;
								if (c[j] == 'w')
									mem_prot |= PROT_WRITE;
								if (c[j] == 'x')
									mem_prot |= PROT_EXEC;
							}
						}
						/* rewrite code if the memory is executable */
						if (mem_prot & PROT_EXEC)
						{
							size_t k;
							for (k = 0; k < strlen(addr); k++)
							{
								if (addr[k] == '-')
								{
									addr[k] = '\0';
									break;
								}
							}
							{
								int64_t from, to;
								from = strtol(&addr[0], NULL, 16);
								if (from == 0)
								{
									/*
									 * this is trampoline code.
									 * so skip it.
									 */
									break;
								}
								to = strtol(&addr[k + 1], NULL, 16);
								disassemble_and_rewrite((char *)from,
														(size_t)to - from,
														mem_prot);
							}
						}
					}
					break;
					}
					if (i == 1)
						break;
					c = strtok(NULL, " ");
					i++;
				}
			}
		}
	}
	fclose(fp);
}

#define NR_syscalls (512) // bigger than max syscall number

static void setup_trampoline(void)
{
	void *mem;

	/* allocate memory at virtual address 0 */
	mem = mmap(0 /* virtual address 0 */, 0x1000,
			   PROT_READ | PROT_WRITE | PROT_EXEC,
			   MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
			   -1, 0);
	if (mem == MAP_FAILED)
	{
		fprintf(stderr, "map failed\n");
		fprintf(stderr, "NOTE: /proc/sys/vm/mmap_min_addr should be set 0\n");
		exit(1);
	}

	{
		int i;
		for (i = 0; i < NR_syscalls; i++)
			((uint8_t *)mem)[i] = 0x90; // NOP
	}
	// 49 bb [64-bit addr (8-byte)]    movabs [64-bit addr (8-byte)],%r11
	((uint8_t *)mem)[NR_syscalls + 0x00] = 0x49;
	((uint8_t *)mem)[NR_syscalls + 0x01] = 0xbb;
	// function pointer push in
	uint64_t asm_syscall_hook_addr = (uint64_t)asm_syscall_hook;
	for (int i = 0; i < 8; i++)
		((uint8_t *)mem)[NR_syscalls + 0x02 + i] = (asm_syscall_hook_addr >> (8 * i)) & 0xff;

	// jmp *%r11
	((uint8_t *)mem)[NR_syscalls + 0x0a] = 0x41;
	((uint8_t *)mem)[NR_syscalls + 0x0b] = 0xff;
	((uint8_t *)mem)[NR_syscalls + 0x0c] = 0xe3;

	/*
	 * mprotect(PROT_EXEC without PROT_READ), executed
	 * on CPUs supporting Memory Protection Keys for Userspace (PKU),
	 * configures this memory region as eXecute-Only-Memory (XOM).
	 * this enables to cause a segmentation fault for a NULL pointer access.
	 */
	assert(!mprotect(0, 0x1000, PROT_EXEC));
}

__attribute__((constructor)) static void __zpoline_init(void)
{
	setup_trampoline();
	rewrite_code();
}
