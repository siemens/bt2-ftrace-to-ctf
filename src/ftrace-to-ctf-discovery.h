/**
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: MIT
 *
 * Discovery of CTF trace directories below a given path using the
 * babeltrace.support-info query object. This resembles the autodisc
 * logic from babeltrace2, which is not available in the C API.
 */

#ifndef _BT_FTRACE_DISCOVERY_H
#define _BT_FTRACE_DISCOVERY_H

#include <babeltrace2/babeltrace.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * A discovered CTF trace directory together with the support-info "group" it
 * belongs to. Directories sharing a non-NULL group form a single logical trace
 * and must be given to one source component; a NULL group is unique.
 */
typedef struct {
	char *path;
	char *group;
} lttng_trace_input;

typedef struct {
	lttng_trace_input *items;
	size_t count;
	size_t cap;
} lttng_trace_list;

/*
 * Recursively walk 'path' and its transitive subdirectories. Every directory
 * that the source component class reports it can handle (support weight > 0) is
 * appended to 'list' together with its group; the walk does not descend into a
 * handled directory. Directories that cannot be handled are skipped and their
 * children are inspected instead. Decisions are logged when 'verbose' is set.
 */
void discover_lttng_inputs(const bt_component_class_source *cls,
						   const char *path, lttng_trace_list *list,
						   int loglevel, bool verbose);

/* Free all entries of 'list' and reset it to empty. */
void lttng_trace_list_clear(lttng_trace_list *list);

#endif
