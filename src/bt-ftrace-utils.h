/**
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef _BT_FTRACE_UTILS_H
#define _BT_FTRACE_UTILS_H

#include <stdbool.h>
#include <string.h>
#include <event-parse.h>

/**
 * Architecture of the traced machine
 */
enum ftrace_arch {
	FTRACE_ARCH_UNKNOWN = 0,
	FTRACE_ARCH_X86,
	FTRACE_ARCH_OTHER,
};

/**
 * Returns the architecture of machine, as in uname -m. NULL is unknown.
 */
static inline enum ftrace_arch ftrace_arch_from_machine(const char *machine)
{
	if (!machine)
		return FTRACE_ARCH_UNKNOWN;
	if (strcmp(machine, "x86_64") == 0 ||
		(strlen(machine) == 4 && machine[0] == 'i' &&
		 strcmp(machine + 2, "86") == 0))
		return FTRACE_ARCH_X86;
	return FTRACE_ARCH_OTHER;
}

/**
 * Returns 1 if the event has the given prefix, 0 otherwise
 */
static inline int event_has_prefix(const char *prefix,
								   const struct tep_event *event)
{
	if (strncmp(prefix, event->name, strlen(prefix)) == 0) {
		return true;
	}
	return false;
}

/**
 * Returns 1 if the event system matches name (string comparison)
 */
static inline int event_system_is(const char *name,
								  const struct tep_event *event)
{
	if (strcmp(name, event->system) == 0) {
		return true;
	}
	return false;
}

#endif
