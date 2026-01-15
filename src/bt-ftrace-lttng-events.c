/**
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "bt-ftrace-lttng-events.h"

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

	strcpy(outbuf, field_name);
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

static int event_has_prefix(const char *prefix, const struct tep_event *event)
{
	if (strncmp(prefix, event->name, strlen(prefix)) == 0) {
		return true;
	}
	return false;
}

static int event_system_is(const char *name, const struct tep_event *event)
{
	if (strncmp(name, event->system, strlen(name)) == 0) {
		return true;
	}
	return false;
}

const char *event_prefix_name(const char *prefix, const struct tep_event *event)
{
	static char outbuf[64];
	snprintf(outbuf, sizeof(outbuf) - 1, "%s%s", prefix, event->name);
	return outbuf;
}

const char *lttng_get_event_name_from_event(const struct tep_event *event)
{
	if (event_system_is("irq", event) && !event_has_prefix("irq_", event)) {
		return event_prefix_name("irq_", event);
	} else if (event_system_is("timer", event) &&
			   !event_has_prefix("timer_", event)) {
		return event_prefix_name("timer_", event);
	} else if (event_system_is("kmem", event) &&
			   !event_has_prefix("kmem_", event)) {
		return event_prefix_name("kmem_", event);
	}
	return event->name;
}

const char *lttng_get_field_name_from_event(const struct tep_event *event,
											const char *field_name)
{
	return lttng_field_name_replace_pid_by_tid(field_name);
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
	/* LTTng prios are shown as observed by userspace */
	if ((strcmp(event->system, "sched") == 0) && strstr(field_name, "prio")) {
		return val - MAX_RT_PRIO;
	}
	return val;
}
