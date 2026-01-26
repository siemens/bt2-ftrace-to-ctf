/**
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "bt-ftrace-sym-field.h"
#include "bt-ftrace-utils.h"

void event_set_symbolic_field(struct tep_event *event, struct tep_record *rec,
							  struct trace_seq *seq, bt_field *field,
							  const char *name)
{
	trace_seq_reset(seq);
	tep_print_func_field(seq, "%s", event, name, rec, 0);
	trace_seq_terminate(seq);
	bt_field_string_set_value(field, seq->buffer);
}
