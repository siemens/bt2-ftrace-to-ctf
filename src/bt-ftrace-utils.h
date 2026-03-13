/**
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef _BT_FTRACE_UTILS_H
#define _BT_FTRACE_UTILS_H

#include <stdbool.h>
#include <event-parse.h>

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
	if (strncmp(name, event->system, strlen(name)) == 0) {
		return true;
	}
	return false;
}

#endif
