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
// #define SUPPLEMENTAL__REWRITTEN_ADDR_CHECK 1
#include <dis-asm.h>
#include <sched.h>
#include <dlfcn.h>

void print_message()
{
	printf("Hello from trampoline!\n");
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
	uint64_t print_message_addr = (uint64_t)print_message;
	for (int i = 0; i < 8; i++)
		((uint8_t *)mem)[NR_syscalls + 0x02 + i] = (print_message_addr >> (8 * i)) & 0xff;

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
}
