/**
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef _BT_FTRACE_SYM_FIELD_H
#define _BT_FTRACE_SYM_FIELD_H

#include <event-parse.h>
#include <babeltrace2/babeltrace.h>
#include <inttypes.h>

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
 * Format a function address as "func_name+0xoffset" or "0x<addr>" if unknown.
 */
static inline void format_func_addr(struct tep_handle *tep,
									struct trace_seq *seq, uint64_t addr)
{
	const char *func = tep_find_function(tep, addr);
	trace_seq_reset(seq);
	if (func) {
		unsigned long long func_addr = tep_find_function_address(tep, addr);
		unsigned long long offset = addr - func_addr;
		if (offset)
			trace_seq_printf(seq, "%s+0x%llx", func, offset);
		else
			trace_seq_printf(seq, "%s", func);
	} else {
		trace_seq_printf(seq, "0x%" PRIx64, addr);
	}
	trace_seq_terminate(seq);
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
