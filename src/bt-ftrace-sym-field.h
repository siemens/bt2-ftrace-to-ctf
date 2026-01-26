/**
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef _BT_FTRACE_SYM_FIELD_H
#define _BT_FTRACE_SYM_FIELD_H

#include <event-parse.h>
#include <babeltrace2/babeltrace.h>

#include "bt-ftrace-utils.h"

/**
 * Returns 1 if the selected event field is a function address.
 */
static inline int event_field_is_symbolic(struct tep_event *event,
										  const char *name)
{
	if (event_system_is("ftrace", event) &&
		event_has_prefix("funcgraph_", event) && (strcmp(name, "func") == 0))
		return 1;
	return 0;
}

/**
 * Sets the symbolized value for a field in the event payload. If the
 * field needs to be symbolized is defined within this function.
 *
 * Logic needs to be in sync with \c event_class_append_sym_fields.
 */
void event_set_symbolic_field(struct tep_event *event, struct tep_record *rec,
							  struct trace_seq *seq, bt_field *field,
							  const char *name);

#endif
