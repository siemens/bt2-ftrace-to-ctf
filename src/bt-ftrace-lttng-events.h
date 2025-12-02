/**
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef _BT_FTRACE_LTTNG_EVENTS_H
#define _BT_FTRACE_LTTNG_EVENTS_H

#include <babeltrace2/babeltrace.h>
#include <event-parse.h>

/**
 * LTTng events are named after their lttng kernel tracepoints, but we have
 * names from the kernels tracefs. Map them for well-known events. Usually,
 * that is just the event name without the event system.
 */
const char *lttng_get_event_name_from_event(const struct tep_event *event);

/**
 * Some event fields are named differently in LTTng. Examples are pid / tid,
 * whereby the kernel uses pid and LTTng consistently uses tid.
 */
const char *lttng_get_field_name_from_event(const struct tep_event *event,
											const char *field_name);

/**
 * Some event values are different on LTTng and the kernel trace. Examples are
 * the prio fields, whereby LTTng's priorities refer to the ones observed from
 * userspace.
 */
uint64_t lttng_get_field_val_from_event_unsigned(const struct tep_event *event,
												 const char *field_name,
												 uint64_t val);

int64_t lttng_get_field_val_from_event_signed(const struct tep_event *event,
											  const char *field_name,
											  int64_t val);

#endif
