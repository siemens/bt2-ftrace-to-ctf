/**
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "bt-ftrace-lttng-events.h"
#include "bt-ftrace-utils.h"

#include <string.h>

/* defined in linux/sched/rt.h */
#define MAX_RT_PRIO 100

static const char *lttng_field_name_replace_pid_by_tid(const char *field_name)
{
	static char outbuf[64];
	const char from[] = "pid";
	const char to[] = "tid";

	if (!field_name)
		return NULL;

	snprintf(outbuf, sizeof(outbuf), "%s", field_name);
	for (char *p = outbuf; *p != '\0'; ++p) {
		if (p[0] == from[0] && p[1] == from[1] && p[2] == from[2]) {
			/* We have found "pid".  Replace it in‑place. */
			p[0] = to[0];
			p[1] = to[1];
			p[2] = to[2];
			break;
		}
	}
	return outbuf;
}

const char *event_prefix_name(const char *prefix, const struct tep_event *event)
{
	static char outbuf[64];
	snprintf(outbuf, sizeof(outbuf) - 1, "%s%s", prefix, event->name);
	return outbuf;
}

const char *event_syscall_prefix_name(const struct tep_event *event)
{
	static char outbuf[64];
	const char *event_name = event->name;
	const char *prefix = NULL;

	if (!event_has_prefix("sys_", event))
		return event_name;

	if (event_has_prefix("sys_enter", event)) {
		prefix = "syscall_entry";
		event_name = event->name + 9;
	} else {
		prefix = "syscall_";
		event_name = event->name + 4;
	}

	snprintf(outbuf, sizeof(outbuf) - 1, "%s%s", prefix, event_name);
	return outbuf;
}

const char *lttng_get_event_name_from_event(const struct tep_event *event,
											enum ftrace_arch arch)
{
	const bool arch_x86 = (arch == FTRACE_ARCH_X86);

	if (event_system_is("irq", event) && !event_has_prefix("irq_", event)) {
		return event_prefix_name("irq_", event);
	} else if (event_system_is("timer", event) &&
			   !event_has_prefix("timer_", event)) {
		return event_prefix_name("timer_", event);
	} else if (event_system_is("kmem", event) &&
			   !event_has_prefix("kmem_", event)) {
		return event_prefix_name("kmem_", event);
	} else if (event_system_is("console", event) &&
			   !event_has_prefix("console_", event)) {
		return event_prefix_name("console_", event);
	} else if (arch_x86 && event_system_is("irq_vectors", event)) {
		return event_prefix_name("x86_irq_vectors_", event);
	} else if (arch_x86 && event_system_is("exceptions", event)) {
		return event_prefix_name("x86_exceptions_", event);
	} else if (event_system_is("syscalls", event) ||
			   event_system_is("raw_syscalls", event)) {
		return event_syscall_prefix_name(event);
	}
	return event->name;
}

const char *lttng_get_field_name_from_event(const struct tep_event *event,
											const char *field_name)
{
	if (strcmp(field_name, "common_pid") == 0)
		return "tid";
	if (strcmp(field_name, "task") == 0)
		return "procname";
	if (strcmp(field_name, "kernel_stack") == 0)
		return "_callstack_kernel";
	if (strcmp(field_name, "user_stack") == 0)
		return "_callstack_user";
	/* LTTng keeps the kernel's names of syscall arguments. */
	if (event_system_is("syscalls", event))
		return field_name;
	return lttng_field_name_replace_pid_by_tid(field_name);
}

struct syscall_arg_type {
	const char *name;
	unsigned int bits;
	bool is_signed;
};

/* Width of the traced kernel's long, i.e. of the field storing the argument. */
#define SYSCALL_ARG_LONG_BITS 0

/*
 * Kernel types of syscall arguments, resolved through
 * include/linux/types.h, include/uapi/asm-generic/posix_types.h,
 * include/uapi/linux/posix_types.h, include/uapi/asm-generic/int-ll64.h,
 * include/linux/key.h, include/linux/quota.h, include/linux/fs.h and
 * include/uapi/linux/aio_abi.h.
 */
static const struct syscall_arg_type syscall_arg_types[] = {
	{ "int", 32, true },
	{ "pid_t", 32, true },
	{ "clockid_t", 32, true },
	{ "timer_t", 32, true },
	{ "mqd_t", 32, true },
	{ "key_t", 32, true },
	{ "key_serial_t", 32, true },
	{ "rwf_t", 32, true },
	{ "__s32", 32, true },
	{ "unsigned int", 32, false },
	{ "unsigned", 32, false },
	{ "u32", 32, false },
	{ "__u32", 32, false },
	{ "uid_t", 32, false },
	{ "gid_t", 32, false },
	{ "qid_t", 32, false },
	{ "umode_t", 16, false },
	{ "long", SYSCALL_ARG_LONG_BITS, true },
	{ "off_t", SYSCALL_ARG_LONG_BITS, true },
	{ "unsigned long", SYSCALL_ARG_LONG_BITS, false },
	{ "size_t", SYSCALL_ARG_LONG_BITS, false },
	{ "aio_context_t", SYSCALL_ARG_LONG_BITS, false },
	{ "loff_t", 64, true },
	{ "u64", 64, false },
	{ "__u64", 64, false },
};

bool lttng_get_syscall_arg_type(const struct tep_event *event,
								const struct tep_format_field *field,
								unsigned int *bits, bool *is_signed)
{
	static const char const_prefix[] = "const ";
	static const char const_suffix[] = " const";
	const size_t prefix_len = sizeof(const_prefix) - 1;
	const size_t suffix_len = sizeof(const_suffix) - 1;
	const char *type = field->type;
	size_t len;

	if (!event_system_is("syscalls", event) || !type ||
		(field->flags &
		 (TEP_FIELD_IS_POINTER | TEP_FIELD_IS_ARRAY | TEP_FIELD_IS_STRING)) ||
		strchr(type, '*'))
		return false;
	if (strncmp(type, const_prefix, prefix_len) == 0)
		type += prefix_len;
	len = strlen(type);
	if (len > suffix_len && strcmp(type + len - suffix_len, const_suffix) == 0)
		len -= suffix_len;
	for (size_t i = 0;
		 i < sizeof(syscall_arg_types) / sizeof(syscall_arg_types[0]); i++) {
		if (strlen(syscall_arg_types[i].name) == len &&
			strncmp(type, syscall_arg_types[i].name, len) == 0) {
			const unsigned int field_bits = field->size * 8;
			const unsigned int arg_bits = syscall_arg_types[i].bits;

			/* ftrace stores no more of an argument than a long. */
			*bits = arg_bits == SYSCALL_ARG_LONG_BITS || arg_bits > field_bits ?
						field_bits :
						arg_bits;
			*is_signed = syscall_arg_types[i].is_signed;
			return true;
		}
	}
	return false;
}

uint64_t lttng_get_field_val_from_event_unsigned(const struct tep_event *event,
												 const char *field_name,
												 uint64_t val)
{
	return val;
}

int64_t lttng_get_field_val_from_event_signed(const struct tep_event *event,
											  const char *field_name,
											  int64_t val)
{
	/* LTTng scheduler priorities are kernel priorities minus MAX_RT_PRIO. */
	if ((strcmp(event->system, "sched") == 0) && strstr(field_name, "prio")) {
		return val - MAX_RT_PRIO;
	}
	return val;
}
