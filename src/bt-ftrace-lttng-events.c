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

const char *lttng_get_event_name_from_event(const struct tep_event *event)
{
	static char outbuf[64];
	if (strncmp("softirq", event->name, sizeof("softirq") - 1) == 0) {
		snprintf(outbuf, sizeof(outbuf) - 1, "irq_%s", event->name);
		return outbuf;
	}
	return event->name;
}

const char *lttng_get_field_name_from_event(const struct tep_event *event,
											const char *field_name)
{
	return lttng_field_name_replace_pid_by_tid(field_name);
}

unsigned long long lttng_get_field_val_from_event(const struct tep_event *event,
												  const char *field_name,
												  unsigned long long val)
{
	/* LTTng prios are shown as observed by userspace */
	if (strstr(field_name, "prio")) {
		return val - MAX_RT_PRIO;
	}
	return val;
}
