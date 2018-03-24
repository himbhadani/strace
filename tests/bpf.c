/*
 * Check bpf syscall decoding.
 *
 * Copyright (c) 2015-2017 Dmitry V. Levin <ldv@altlinux.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "tests.h"
#include <asm/unistd.h>
#include "scno.h"

#if defined __NR_bpf

# include <stddef.h>
# include <stdio.h>
# include <stdint.h>
# include <string.h>
# include <unistd.h>

# ifdef HAVE_LINUX_BPF_H
#  include <linux/bpf.h>
# endif

# include "print_fields.h"

# define BPF_ATTR_SIZE MAX(72, sizeof(union bpf_attr))

# ifndef HAVE_BPF_MAP_CREATE
#  define BPF_MAP_CREATE 0
# endif
# ifndef HAVE_BPF_MAP_LOOKUP_ELEM
#  define BPF_MAP_LOOKUP_ELEM 1
# endif
# ifndef HAVE_BPF_MAP_UPDATE_ELEM
#  define BPF_MAP_UPDATE_ELEM 2
# endif
# ifndef HAVE_BPF_MAP_DELETE_ELEM
#  define BPF_MAP_DELETE_ELEM 3
# endif
# ifndef HAVE_BPF_MAP_GET_NEXT_KEY
#  define BPF_MAP_GET_NEXT_KEY 4
# endif
# ifndef HAVE_BPF_PROG_LOAD
#  define BPF_PROG_LOAD 5
# endif
# ifndef HAVE_BPF_OBJ_PIN
#  define BPF_OBJ_PIN 6
# endif
# ifndef HAVE_BPF_OBJ_GET
#  define BPF_OBJ_GET 7
# endif
# ifndef HAVE_BPF_PROG_ATTACH
#  define BPF_PROG_ATTACH 8
# endif
# ifndef HAVE_BPF_PROG_DETACH
#  define BPF_PROG_DETACH 9
# endif
# ifndef HAVE_BPF_PROG_TEST_RUN
#  define BPF_PROG_TEST_RUN 10
# endif
# ifndef HAVE_BPF_PROG_GET_NEXT_ID
#  define BPF_PROG_GET_NEXT_ID 11
# endif
# ifndef HAVE_BPF_MAP_GET_NEXT_ID
#  define BPF_MAP_GET_NEXT_ID 12
# endif
# ifndef HAVE_BPF_PROG_GET_FD_BY_ID
#  define BPF_PROG_GET_FD_BY_ID 13
# endif
# ifndef HAVE_BPF_MAP_GET_FD_BY_ID
#  define BPF_MAP_GET_FD_BY_ID 14
# endif
# ifndef HAVE_BPF_OBJ_GET_INFO_BY_FD
#  define BPF_OBJ_GET_INFO_BY_FD 15
# endif
# ifndef HAVE_BPF_PROG_QUERY
#  define BPF_PROG_QUERY 16
# endif

# ifndef HAVE_UNION_BPF_ATTR
union bpf_attr {
	struct {
		uint32_t map_type;
		uint32_t key_size;
		uint32_t value_size;
		uint32_t max_entries;
	};
};
# endif

# ifndef HAVE_STRUCT_BPF_INSN
struct bpf_insn {
	uint8_t code;
	uint8_t dst_reg:4;
	uint8_t src_reg:4;
	int16_t off;
	int32_t imm;
};
# endif

# ifndef BPF_JMP
#  define BPF_JMP 0x5
# endif
# ifndef BPF_EXIT
#  define BPF_EXIT 0x90
# endif

union bpf_attr_data {
	union bpf_attr attr;
	char     char_data[BPF_ATTR_SIZE];
	uint32_t u32_data[BPF_ATTR_SIZE / sizeof(uint32_t)];
	uint64_t u64_data[BPF_ATTR_SIZE / sizeof(uint64_t)];
};

struct bpf_check {
	kernel_ulong_t cmd;
	const char *cmd_str;
	unsigned int (*init_fn)(union bpf_attr_data *data, const size_t idx);
	void (*print_fn)(union bpf_attr_data *data,
			 union bpf_attr_data *addr, const size_t idx);
	const char **str;
	size_t count;
};


static const kernel_ulong_t long_bits = (kernel_ulong_t) 0xfacefeed00000000ULL;
static const char *errstr;
static unsigned int sizeof_attr = sizeof(union bpf_attr);
static unsigned int page_size;
static unsigned long end_of_page;

static long
sys_bpf(kernel_ulong_t cmd, kernel_ulong_t attr, kernel_ulong_t size)
{
	long rc = syscall(__NR_bpf, cmd, attr, size);
	errstr = sprintrc(rc);
	return rc;
}

# if VERBOSE
#  define print_extra_data(addr_, offs_, size_) \
	do { \
		printf("/* bytes %u..%u */ ", (offs_), (size_) + (offs_) - 1); \
		print_quoted_hex((addr_) + (offs_), (size_)); \
	} while (0)
# else
#  define print_extra_data(addr_, offs_, size_) printf("...")
#endif

static void
print_bpf_attr(const struct bpf_check *check, union bpf_attr_data *data,
	       unsigned long ptr, size_t idx)
{
	if (check->print_fn)
		check->print_fn(data, (union bpf_attr_data *) ptr, idx);
	else
		printf("%s", check->str[idx]);
}

static void
test_bpf(const struct bpf_check *check)
{
	union bpf_attr_data data;
	unsigned int offset = 0;
	const size_t last = check->count - 1;

	/* zero addr */
	sys_bpf(check->cmd, 0, long_bits | sizeof(union bpf_attr));
	printf("bpf(%s, NULL, %u) = %s\n",
	       check->cmd_str, sizeof_attr, errstr);

	/* zero size */
	unsigned long addr = end_of_page - sizeof_attr;
	sys_bpf(check->cmd, addr, long_bits);
	printf("bpf(%s, %#lx, 0) = %s\n",
	       check->cmd_str, addr, errstr);

	for (size_t i = 0; i < check->count; i++) {
		offset = check->init_fn(&data, i);

		addr = end_of_page - offset;
		memcpy((void *) addr, &data, offset);

		/* starting piece of union bpf_attr */
		sys_bpf(check->cmd, addr, offset);
		printf("bpf(%s, {", check->cmd_str);
		print_bpf_attr(check, &data, addr, i);
		printf("}, %u) = %s\n", offset, errstr);

		/* short read of the starting piece */
		sys_bpf(check->cmd, addr + 1, offset);
		printf("bpf(%s, %#lx, %u) = %s\n",
		       check->cmd_str, addr + 1, offset, errstr);
	}

	if (offset < sizeof_attr) {
		/* short read of the whole union bpf_attr */
		memcpy((void *) end_of_page - sizeof_attr + 1, &data, offset);
		addr = end_of_page - sizeof_attr + 1;
		memset((void *) addr + offset, 0, sizeof_attr - offset - 1);
		sys_bpf(check->cmd, addr, sizeof_attr);
		printf("bpf(%s, %#lx, %u) = %s\n",
		       check->cmd_str, addr, sizeof_attr, errstr);

		/* the whole union bpf_attr */
		memcpy((void *) end_of_page - sizeof_attr, &data, offset);
		addr = end_of_page - sizeof_attr;
		memset((void *) addr + offset, 0, sizeof_attr - offset);
		sys_bpf(check->cmd, addr, sizeof_attr);
		printf("bpf(%s, {", check->cmd_str);
		print_bpf_attr(check, &data, addr, last);
		printf("}, %u) = %s\n", sizeof_attr, errstr);

		/* non-zero bytes after the relevant part */
		fill_memory_ex((void *) addr + offset,
			       sizeof_attr - offset, '0', 10);
		sys_bpf(check->cmd, addr, sizeof_attr);
		printf("bpf(%s, {", check->cmd_str);
		print_bpf_attr(check, &data, addr, last);
		printf(", ");
		print_extra_data((char *) addr, offset,
				 sizeof_attr - offset);
		printf("}, %u) = %s\n", sizeof_attr, errstr);
	}

	/* short read of the whole page */
	memcpy((void *) end_of_page - page_size + 1, &data, offset);
	addr = end_of_page - page_size + 1;
	memset((void *) addr + offset, 0, page_size - offset - 1);
	sys_bpf(check->cmd, addr, page_size);
	printf("bpf(%s, %#lx, %u) = %s\n",
	       check->cmd_str, addr, page_size, errstr);

	/* the whole page */
	memcpy((void *) end_of_page - page_size, &data, offset);
	addr = end_of_page - page_size;
	memset((void *) addr + offset, 0, page_size - offset);
	sys_bpf(check->cmd, addr, page_size);
	printf("bpf(%s, {", check->cmd_str);
	print_bpf_attr(check, &data, addr, last);
	printf("}, %u) = %s\n", page_size, errstr);

	/* non-zero bytes after the whole union bpf_attr */
	fill_memory_ex((void *) addr + offset,
		       page_size - offset, '0', 10);
	sys_bpf(check->cmd, addr, page_size);
	printf("bpf(%s, {", check->cmd_str);
	print_bpf_attr(check, &data, addr, last);
	printf(", ");
	print_extra_data((char *) addr, offset,
			 page_size - offset);
	printf("}, %u) = %s\n", page_size, errstr);

	/* more than a page */
	sys_bpf(check->cmd, addr, page_size + 1);
	printf("bpf(%s, %#lx, %u) = %s\n",
	       check->cmd_str, addr, page_size + 1, errstr);
}


static unsigned int
init_BPF_MAP_CREATE_attr(union bpf_attr_data *data, const size_t idx)
{
	switch (idx) {
	case 0:
		data->attr.map_type = 2;
		return offsetofend(union bpf_attr, map_type);

	case 1:
		data->attr.map_type = 1;
		data->attr.key_size = 4;
		data->attr.value_size = 8;
		data->attr.max_entries = 256;
# ifdef HAVE_UNION_BPF_ATTR_MAP_FLAGS
		data->attr.map_flags
# else
		data->u32_data[4]
# endif
			= 7;
# ifdef HAVE_UNION_BPF_ATTR_INNER_MAP_FD
		data->attr.inner_map_fd
# else
		data->u32_data[5]
# endif
			= -1;
# ifdef HAVE_UNION_BPF_ATTR_NUMA_NODE
		data->attr.numa_node
# else
		data->u32_data[6]
# endif
			= 42;
		return
# ifdef HAVE_UNION_BPF_ATTR_NUMA_NODE
			offsetofend(union bpf_attr, numa_node)
# else
			28
# endif
			;
	}

	return -1U;
}

static const char *BPF_MAP_CREATE_strs[] = {
	"map_type=BPF_MAP_TYPE_ARRAY, key_size=0, value_size=0"
		", max_entries=0, map_flags=0, inner_map_fd=0",
	"map_type=BPF_MAP_TYPE_HASH, key_size=4"
		", value_size=8, max_entries=256"
		", map_flags=BPF_F_NO_PREALLOC|BPF_F_NO_COMMON_LRU"
		"|BPF_F_NUMA_NODE, inner_map_fd=-1, numa_node=42",
};

# define print_BPF_MAP_CREATE_attr NULL


static unsigned int
init_BPF_MAP_LOOKUP_ELEM_attr(union bpf_attr_data *data, const size_t idx)
{
	switch (idx) {
	case 0:
# ifdef HAVE_UNION_BPF_ATTR_MAP_FD
		data->attr.map_fd
# else
		data->u32_data[0]
# endif
			= -1;
		return
# ifdef HAVE_UNION_BPF_ATTR_MAP_FD
			offsetofend(union bpf_attr, map_fd)
# else
			4
# endif
			;

	case 1:
# ifdef HAVE_UNION_BPF_ATTR_MAP_FD
		data->attr.map_fd
# else
		data->u32_data[0]
# endif
			= -1;
# ifdef HAVE_UNION_BPF_ATTR_KEY
		data->attr.key
# else
		data->u64_data[1]
# endif
			= 0xdeadbeef;
# ifdef HAVE_UNION_BPF_ATTR_VALUE
		data->attr.value
# else
		data->u64_data[2]
# endif
			= 0xbadc0ded;
		return
# ifdef HAVE_UNION_BPF_ATTR_VALUE
			offsetofend(union bpf_attr, value)
# else
			24
# endif
			;
	}

	return -1U;
}

static const char *BPF_MAP_LOOKUP_ELEM_strs[] = {
	"map_fd=-1, key=0, value=0",
	"map_fd=-1, key=0xdeadbeef, value=0xbadc0ded",
};

# define print_BPF_MAP_LOOKUP_ELEM_attr NULL


static unsigned int
init_BPF_MAP_UPDATE_ELEM_attr(union bpf_attr_data *data, const size_t idx)
{
	switch (idx) {
	case 0:
# ifdef HAVE_UNION_BPF_ATTR_MAP_FD
		data->attr.map_fd
# else
		data->u32_data[0]
# endif
			= -1;
		return
# ifdef HAVE_UNION_BPF_ATTR_MAP_FD
			offsetofend(union bpf_attr, map_fd)
# else
			4
# endif
			;

	case 1:
# ifdef HAVE_UNION_BPF_ATTR_MAP_FD
		data->attr.map_fd
# else
		data->u32_data[0]
# endif
			= -1;
# ifdef HAVE_UNION_BPF_ATTR_KEY
		data->attr.key
# else
		data->u64_data[1]
# endif
			= 0xdeadbeef;
# ifdef HAVE_UNION_BPF_ATTR_VALUE
		data->attr.value
# else
		data->u64_data[2]
# endif
			= 0xbadc0ded;
# ifdef HAVE_UNION_BPF_ATTR_FLAGS
		data->attr.flags
# else
		data->u64_data[3]
# endif
			= 2;
		return
# ifdef HAVE_UNION_BPF_ATTR_FLAGS
			offsetofend(union bpf_attr, flags)
# else
			32
# endif
			;
	}

	return -1U;
}

static const char *BPF_MAP_UPDATE_ELEM_strs[] = {
	"map_fd=-1, key=0, value=0, flags=BPF_ANY",
	"map_fd=-1, key=0xdeadbeef, value=0xbadc0ded, flags=BPF_EXIST",
};

# define print_BPF_MAP_UPDATE_ELEM_attr NULL


static unsigned int
init_BPF_MAP_DELETE_ELEM_attr(union bpf_attr_data *data, const size_t idx)
{
	switch (idx) {
	case 0:
# ifdef HAVE_UNION_BPF_ATTR_MAP_FD
		data->attr.map_fd
# else
		data->u32_data[0]
# endif
			= -1;
		return
# ifdef HAVE_UNION_BPF_ATTR_MAP_FD
			offsetofend(union bpf_attr, map_fd)
# else
			4
# endif
			;

	case 1:
# ifdef HAVE_UNION_BPF_ATTR_MAP_FD
		data->attr.map_fd
# else
		data->u32_data[0]
# endif
			= -1;
# ifdef HAVE_UNION_BPF_ATTR_KEY
		data->attr.key
# else
		data->u64_data[1]
# endif
			= 0xdeadbeef;
		return
# ifdef HAVE_UNION_BPF_ATTR_KEY
			offsetofend(union bpf_attr, key)
# else
			16
# endif
			;
	}

	return -1U;
}

static const char *BPF_MAP_DELETE_ELEM_strs[] = {
	"map_fd=-1, key=0",
	"map_fd=-1, key=0xdeadbeef",
};

# define print_BPF_MAP_DELETE_ELEM_attr NULL


static unsigned int
init_BPF_MAP_GET_NEXT_KEY_attr(union bpf_attr_data *data, const size_t idx)
{
	switch (idx) {
	case 0:
# ifdef HAVE_UNION_BPF_ATTR_MAP_FD
		data->attr.map_fd
# else
		data->u32_data[0]
# endif
			= -1;
		return
# ifdef HAVE_UNION_BPF_ATTR_MAP_FD
			offsetofend(union bpf_attr, map_fd)
# else
			4
# endif
			;

	case 1:
# ifdef HAVE_UNION_BPF_ATTR_MAP_FD
		data->attr.map_fd
# else
		data->u32_data[0]
# endif
			= -1;
# ifdef HAVE_UNION_BPF_ATTR_KEY
		data->attr.key
# else
		data->u64_data[1]
# endif
			= 0xdeadbeef;
# ifdef HAVE_UNION_BPF_ATTR_NEXT_KEY
		data->attr.next_key
# else
		data->u64_data[2]
# endif
			= 0xbadc0ded;
		return
# ifdef HAVE_UNION_BPF_ATTR_NEXT_KEY
			offsetofend(union bpf_attr, next_key)
# else
			24
# endif
			;
	}

	return -1U;
}

static const char *BPF_MAP_GET_NEXT_KEY_strs[] = {
	"map_fd=-1, key=0, next_key=0",
	"map_fd=-1, key=0xdeadbeef, next_key=0xbadc0ded",
};

# define print_BPF_MAP_GET_NEXT_KEY_attr NULL


static const struct bpf_insn insns[] = {
	{ .code = BPF_JMP | BPF_EXIT }
};
static char log_buf[4096];

static unsigned int
init_BPF_PROG_LOAD_attr(union bpf_attr_data *data, const size_t idx)
{
	switch (idx) {
	case 0:
# ifdef HAVE_UNION_BPF_ATTR_PROG_TYPE
		data->attr.prog_type
# else
		data->u32_data[0]
# endif
			= 1;
		return
# ifdef HAVE_UNION_BPF_ATTR_PROG_TYPE
			offsetofend(union bpf_attr, prog_type)
# else
			4
# endif
			;

	case 1:
# ifdef HAVE_UNION_BPF_ATTR_PROG_TYPE
		data->attr.prog_type
# else
		data->u32_data[0]
# endif
			= 1;
# ifdef HAVE_UNION_BPF_ATTR_INSN_CNT
		data->attr.insn_cnt
# else
		data->u32_data[1]
# endif
			= ARRAY_SIZE(insns);
# ifdef HAVE_UNION_BPF_ATTR_INSNS
		data->attr.insns
# else
		data->u64_data[1]
# endif
			= (uintptr_t) insns;
# ifdef HAVE_UNION_BPF_ATTR_LICENSE
		data->attr.license
# else
		data->u64_data[2]
# endif
			= (uintptr_t) "GPL";
# ifdef HAVE_UNION_BPF_ATTR_LOG_LEVEL
		data->attr.log_level
# else
		data->u32_data[6]
# endif
			= 42;
# ifdef HAVE_UNION_BPF_ATTR_LOG_SIZE
		data->attr.log_size
# else
		data->u32_data[7]
# endif
			= sizeof(log_buf);
# ifdef HAVE_UNION_BPF_ATTR_LOG_BUF
		data->attr.log_buf
# else
		data->u64_data[4]
# endif
			= (uintptr_t) log_buf;
# ifdef HAVE_UNION_BPF_ATTR_KERN_VERSION
		data->attr.kern_version
# else
		data->u32_data[10]
# endif
			= 0xcafef00d;
# ifdef HAVE_UNION_BPF_ATTR_PROG_FLAGS
		data->attr.prog_flags
# else
		data->u32_data[11]
# endif
			= 1;
		return
# ifdef HAVE_UNION_BPF_ATTR_PROG_FLAGS
			offsetofend(union bpf_attr, prog_flags)
# else
			48
# endif
			;
	}

	return -1U;
}

static const char *BPF_PROG_LOAD_strs[] = {
	"prog_type=BPF_PROG_TYPE_SOCKET_FILTER, insn_cnt=0, insns=0"
		", license=NULL",
	"",
};

static void
print_BPF_PROG_LOAD_attr(union bpf_attr_data *data, union bpf_attr_data *addr,
			 const size_t idx)
{
	if (idx != 1) {
		printf("%s", BPF_PROG_LOAD_strs[idx]);
		return;
	}

	printf("prog_type=BPF_PROG_TYPE_SOCKET_FILTER, insn_cnt=%u, insns=%p"
	       ", license=\"GPL\", log_level=42, log_size=4096, log_buf=%p"
	       ", kern_version=KERNEL_VERSION(51966, 240, 13)"
	       ", prog_flags=BPF_F_STRICT_ALIGNMENT",
	       (unsigned int) ARRAY_SIZE(insns), insns,
	       log_buf);
}


/*
 * bpf() syscall and its first six commands were introduced in Linux kernel
 * 3.18. Some additional commands were added afterwards, so we need to take
 * precautions to make sure the tests compile.
 *
 * BPF_OBJ_PIN and BPF_OBJ_GET commands appear in kernel 4.4.
 */
static unsigned int
init_BPF_OBJ_PIN_attr(union bpf_attr_data *data, const size_t idx)
{
	switch (idx) {
	case 0:
# ifdef HAVE_UNION_BPF_ATTR_PATHNAME
		data->attr.pathname
# else
		data->u64_data[0]
# endif
			= 0;
		return
# ifdef HAVE_UNION_BPF_ATTR_PATHNAME
			offsetofend(union bpf_attr, pathname)
# else
			8
# endif
			;

	case 1:
# ifdef HAVE_UNION_BPF_ATTR_PATHNAME
		data->attr.pathname
# else
		data->u64_data[0]
# endif
			= (uintptr_t) "/sys/fs/bpf/foo/bar";
# ifdef HAVE_UNION_BPF_ATTR_BPF_FD
		data->attr.bpf_fd
# else
		data->u32_data[2]
# endif
			= -1;
		return
# ifdef HAVE_UNION_BPF_ATTR_BPF_FD
			offsetofend(union bpf_attr, bpf_fd)
# else
			12
# endif
			;
	}

	return -1U;
}

static const char *BPF_OBJ_PIN_strs[] = {
	"pathname=NULL, bpf_fd=0",
	"pathname=\"/sys/fs/bpf/foo/bar\", bpf_fd=-1",
};

# define print_BPF_OBJ_PIN_attr NULL


# define init_BPF_OBJ_GET_attr init_BPF_OBJ_PIN_attr
# define BPF_OBJ_GET_strs BPF_OBJ_PIN_strs
# define print_BPF_OBJ_GET_attr print_BPF_OBJ_PIN_attr


/* BPF_PROG_ATTACH and BPF_PROG_DETACH commands appear in kernel 4.10. */
static unsigned int
init_BPF_PROG_ATTACH_attr(union bpf_attr_data *data, const size_t idx)
{
	switch (idx) {
	case 0:
# ifdef HAVE_UNION_BPF_ATTR_TARGET_FD
		data->attr.target_fd
# else
		data->u32_data[0]
# endif
			= -1;
		return
# ifdef HAVE_UNION_BPF_ATTR_TARGET_FD
			offsetofend(union bpf_attr, target_fd)
# else
			4
# endif
			;

	case 1:
# ifdef HAVE_UNION_BPF_ATTR_TARGET_FD
		data->attr.target_fd
# else
		data->u32_data[0]
# endif
			= -1;
# ifdef HAVE_UNION_BPF_ATTR_ATTACH_BPF_FD
		data->attr.attach_bpf_fd
# else
		data->u32_data[1]
# endif
			= -2;
# ifdef HAVE_UNION_BPF_ATTR_ATTACH_TYPE
		data->attr.attach_type
# else
		data->u32_data[2]
# endif
			= 2;
# ifdef HAVE_UNION_BPF_ATTR_ATTACH_FLAGS
		data->attr.attach_flags
# else
		data->u32_data[3]
# endif
			= 1;
		return
# ifdef HAVE_UNION_BPF_ATTR_ATTACH_FLAGS
			offsetofend(union bpf_attr, attach_flags)
# else
			16
# endif
			;
	}

	return -1U;
}

static const char *BPF_PROG_ATTACH_strs[] = {
	"target_fd=-1, attach_bpf_fd=0"
		", attach_type=BPF_CGROUP_INET_INGRESS, attach_flags=0",
	"target_fd=-1, attach_bpf_fd=-2"
		", attach_type=BPF_CGROUP_INET_SOCK_CREATE"
		", attach_flags=BPF_F_ALLOW_OVERRIDE",
};

# define print_BPF_PROG_ATTACH_attr NULL


static unsigned int
init_BPF_PROG_DETACH_attr(union bpf_attr_data *data, const size_t idx)
{
	switch (idx) {
	case 0:
# ifdef HAVE_UNION_BPF_ATTR_TARGET_FD
		data->attr.target_fd
# else
		data->u32_data[0]
# endif
			= -1;
		return
# ifdef HAVE_UNION_BPF_ATTR_TARGET_FD
			offsetofend(union bpf_attr, target_fd)
# else
			4
# endif
			;

	case 1:
# ifdef HAVE_UNION_BPF_ATTR_TARGET_FD
		data->attr.target_fd
# else
		data->u32_data[0]
# endif
			= -1;
# ifdef HAVE_UNION_BPF_ATTR_ATTACH_TYPE
		data->attr.attach_type
# else
		data->u32_data[2]
# endif
			= 2;
		return
# ifdef HAVE_UNION_BPF_ATTR_ATTACH_TYPE
			offsetofend(union bpf_attr, attach_type)
# else
			12
# endif
			;
	}

	return -1U;
}

static const char *BPF_PROG_DETACH_strs[] = {
	"target_fd=-1, attach_type=BPF_CGROUP_INET_INGRESS",
	"target_fd=-1, attach_type=BPF_CGROUP_INET_SOCK_CREATE",
};

# define print_BPF_PROG_DETACH_attr NULL


/* BPF_PROG_TEST_RUN command appears in kernel 4.12. */
static unsigned int
init_BPF_PROG_TEST_RUN_attr(union bpf_attr_data *data, const size_t idx)
{
	switch (idx) {
	case 0:
# ifdef HAVE_UNION_BPF_ATTR_TEST_PROG_FD
		data->attr.test.prog_fd
# else
		data->u32_data[0]
# endif
			= -1;
		return
# ifdef HAVE_UNION_BPF_ATTR_TEST_PROG_FD
			offsetofend(union bpf_attr, test.prog_fd)
# else
			4
# endif
			;

	case 1:
# ifdef HAVE_UNION_BPF_ATTR_TEST_PROG_FD
		data->attr.test.prog_fd
# else
		data->u32_data[0]
# endif
			= -1;
# ifdef HAVE_UNION_BPF_ATTR_TEST_RETVAL
		data->attr.test.retval
# else
		data->u32_data[1]
# endif
			= 0xfac1fed2;
# ifdef HAVE_UNION_BPF_ATTR_TEST_DATA_SIZE_IN
		data->attr.test.data_size_in
# else
		data->u32_data[2]
# endif
			= 0xfac3fed4;
# ifdef HAVE_UNION_BPF_ATTR_TEST_DATA_SIZE_OUT
		data->attr.test.data_size_out
# else
		data->u32_data[3]
# endif
			= 0xfac5fed6;
# ifdef HAVE_UNION_BPF_ATTR_TEST_DATA_IN
		data->attr.test.data_in
# else
		data->u64_data[2]
# endif
			= (uint64_t) 0xfacef11dbadc2ded;
# ifdef HAVE_UNION_BPF_ATTR_TEST_DATA_OUT
		data->attr.test.data_out
# else
		data->u64_data[3]
# endif
			= (uint64_t) 0xfacef33dbadc4ded;
# ifdef HAVE_UNION_BPF_ATTR_TEST_REPEAT
		data->attr.test.repeat
# else
		data->u32_data[8]
# endif
			= 0xfac7fed8;
# ifdef HAVE_UNION_BPF_ATTR_TEST_DURATION
		data->attr.test.duration
# else
		data->u32_data[9]
# endif
			= 0xfac9feda;
		return
# ifdef HAVE_UNION_BPF_ATTR_TEST_DURATION
			offsetofend(union bpf_attr, test.duration)
# else
			40
# endif
			;
	}

	return -1U;
}

static const char *BPF_PROG_TEST_RUN_strs[] = {
	"test={prog_fd=-1, retval=0, data_size_in=0, data_size_out=0"
		", data_in=0, data_out=0, repeat=0, duration=0}",
	"test={prog_fd=-1, retval=4207017682, data_size_in=4207148756"
		", data_size_out=4207279830, data_in=0xfacef11dbadc2ded"
		", data_out=0xfacef33dbadc4ded, repeat=4207410904"
		", duration=4207541978}",
};

# define print_BPF_PROG_TEST_RUN_attr NULL


static unsigned int
init_BPF_PROG_GET_NEXT_ID_attr(union bpf_attr_data *data, const size_t idx)
{
	switch (idx) {
	case 0:
# ifdef HAVE_UNION_BPF_ATTR_START_ID
		data->attr.start_id
# else
		data->u32_data[0]
# endif
			= 0xdeadbeef;
		return
# ifdef HAVE_UNION_BPF_ATTR_START_ID
			offsetofend(union bpf_attr, start_id)
# else
			4
# endif
			;

	case 1:
# ifdef HAVE_UNION_BPF_ATTR_START_ID
		data->attr.start_id
# else
		data->u32_data[0]
# endif
			= 0xbadc0ded;
# ifdef HAVE_UNION_BPF_ATTR_NEXT_ID
		data->attr.next_id
# else
		data->u32_data[1]
# endif
			= 0xcafef00d;
		return
# ifdef HAVE_UNION_BPF_ATTR_NEXT_ID
			offsetofend(union bpf_attr, next_id)
# else
			8
# endif
			;
	}

	return -1U;
}

static const char *BPF_PROG_GET_NEXT_ID_strs[] = {
	"start_id=3735928559, next_id=0",
	"start_id=3134983661, next_id=3405705229",
};

# define print_BPF_PROG_GET_NEXT_ID_attr NULL


# define init_BPF_MAP_GET_NEXT_ID_attr init_BPF_PROG_GET_NEXT_ID_attr
# define BPF_MAP_GET_NEXT_ID_strs BPF_PROG_GET_NEXT_ID_strs
# define print_BPF_MAP_GET_NEXT_ID_attr print_BPF_PROG_GET_NEXT_ID_attr


# define init_BPF_PROG_GET_FD_BY_ID_attr init_BPF_PROG_GET_NEXT_ID_attr

static const char *BPF_PROG_GET_FD_BY_ID_strs[] = {
	"prog_id=3735928559, next_id=0",
	"prog_id=3134983661, next_id=3405705229",
};

# define print_BPF_PROG_GET_FD_BY_ID_attr NULL


# define init_BPF_MAP_GET_FD_BY_ID_attr init_BPF_PROG_GET_NEXT_ID_attr

static const char *BPF_MAP_GET_FD_BY_ID_strs[] = {
	"map_id=3735928559, next_id=0",
	"map_id=3134983661, next_id=3405705229",
};

# define print_BPF_MAP_GET_FD_BY_ID_attr NULL


static unsigned int
init_BPF_OBJ_GET_INFO_BY_FD_attr(union bpf_attr_data *data, const size_t idx)
{
	switch (idx) {
	case 0:
# ifdef HAVE_UNION_BPF_ATTR_INFO_BPF_FD
		data->attr.info.bpf_fd
# else
		data->u32_data[0]
# endif
			= -1;
		return
# ifdef HAVE_UNION_BPF_ATTR_INFO_BPF_FD
			offsetofend(union bpf_attr, info.bpf_fd)
# else
			4
# endif
			;

	case 1:
# ifdef HAVE_UNION_BPF_ATTR_INFO_BPF_FD
		data->attr.info.bpf_fd
# else
		data->u32_data[0]
# endif
			= -1;
# ifdef HAVE_UNION_BPF_ATTR_INFO_INFO_LEN
		data->attr.info.info_len
# else
		data->u32_data[1]
# endif
			= 0xdeadbeef;
# ifdef HAVE_UNION_BPF_ATTR_INFO_INFO
		data->attr.info.info
# else
		data->u64_data[1]
# endif
			= (uint64_t) 0xfacefeedbadc0ded;
		return
# ifdef HAVE_UNION_BPF_ATTR_INFO_INFO
			offsetofend(union bpf_attr, info.info)
# else
			16
# endif
			;
	}

	return -1U;
}

static const char *BPF_OBJ_GET_INFO_BY_FD_strs[] = {
	"info={bpf_fd=-1, info_len=0, info=0}",
	"info={bpf_fd=-1, info_len=3735928559, info=0xfacefeedbadc0ded}",
};

# define print_BPF_OBJ_GET_INFO_BY_FD_attr NULL


# define CHK(cmd_) \
	{ \
		cmd_, #cmd_, \
		init_##cmd_##_attr, print_##cmd_##_attr, \
		cmd_##_strs, ARRAY_SIZE(cmd_##_strs), \
	} \
	/* End of CHK definition */

int
main(void)
{
	static const struct bpf_check checks[] = {
		CHK(BPF_MAP_CREATE),

		CHK(BPF_MAP_LOOKUP_ELEM),
		CHK(BPF_MAP_UPDATE_ELEM),
		CHK(BPF_MAP_DELETE_ELEM),
		CHK(BPF_MAP_GET_NEXT_KEY),

		CHK(BPF_PROG_LOAD),

		CHK(BPF_OBJ_PIN),
		CHK(BPF_OBJ_GET),

		CHK(BPF_PROG_ATTACH),
		CHK(BPF_PROG_DETACH),

		CHK(BPF_PROG_TEST_RUN),

		CHK(BPF_PROG_GET_NEXT_ID),
		CHK(BPF_MAP_GET_NEXT_ID),
		CHK(BPF_PROG_GET_FD_BY_ID),
		CHK(BPF_MAP_GET_FD_BY_ID),

		CHK(BPF_OBJ_GET_INFO_BY_FD),
	};

	page_size = get_page_size();
	end_of_page = (unsigned long) tail_alloc(1) + 1;

	for (size_t i = 0; i < ARRAY_SIZE(checks); i++)
		test_bpf(checks + i);

	sys_bpf(0xfacefeed, 0, (kernel_ulong_t) 0xfacefeedbadc0dedULL);
	printf("bpf(0xfacefeed /* BPF_??? */, NULL, %u) = %s\n",
	       0xbadc0dedu, errstr);

	sys_bpf(0xfacefeed, end_of_page, 40);
	printf("bpf(0xfacefeed /* BPF_??? */, %#lx, 40) = %s\n",
	       end_of_page, errstr);

	puts("+++ exited with 0 +++");
	return 0;
}

#else

SKIP_MAIN_UNDEFINED("__NR_bpf")

#endif
