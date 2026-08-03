/**
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef _BT_FTRACE_COMMON_H
#define _BT_FTRACE_COMMON_H

#include <babeltrace2/babeltrace.h>
#include <event-parse.h>
#include <glib.h>

#define FTRACE_CLOCK_UUID_NAMESPACE                     \
	{                                                   \
		0xfc, 0xc2, 0xb9, 0xca, 0x5f, 0x9d, 0x4e, 0x51, \
		0x82, 0xdc, 0x0e, 0x97, 0x41, 0x98, 0x54, 0xbc, \
	}

#define FTRACE_TRACE_UUID_NAMESPACE                     \
	{                                                   \
		0x1b, 0x02, 0x8a, 0x6a, 0x47, 0x7c, 0x4a, 0xa9, \
		0x98, 0xa8, 0x92, 0x2b, 0xe8, 0xcf, 0x77, 0x78, \
	}

#define FTRACE_NAMESPACE "ftrace"

struct ftrace_common_config {
	bt_bool lttng_format;
	bt_bool symbolize_funcs;
	bt_bool with_callstacks;
	bt_logging_level log_level;
	uint64_t mip_version;
};

struct ftrace_pending_stack {
	uint64_t *kernel_stack;
	int klen;
	uint64_t *user_stack;
	int ulen;
};

struct ftrace_common_options {
	struct ftrace_common_config config;
	uint64_t clock_offset_ns;
	char *clock_uid;
	char *clock_namespace;
	char *clock_name;
	char *trace_name;
	char *trace_creation_datetime;
};

void ftrace_parse_common_params(const bt_value *params,
								struct ftrace_common_options *options);

bt_event_class *
ftrace_create_event_class(bt_stream_class *stream_class,
						  struct tep_event *event,
						  const struct ftrace_common_config *config);

bt_stream_class *ftrace_create_stream_class(bt_trace_class *trace_class,
											bt_clock_class *clock_class,
											bt_bool supports_packets);

GHashTable *
ftrace_create_event_classes(struct tep_handle *tep,
							bt_stream_class *stream_class,
							const struct ftrace_common_config *config);

void ftrace_set_trace_environment(
	bt_trace *trace, const struct ftrace_common_config *config,
	const char *sysname, const char *kernel_release, const char *hostname,
	const char *trace_name, const char *trace_creation_datetime,
	int tracer_version_major, int tracer_version_minor);

void ftrace_configure_clock(bt_clock_class *clock_class,
							const char *input_clock_name,
							const char *clock_name_override,
							uint64_t clock_offset_ns, const char *clock_uid,
							const char *clock_namespace, uint64_t mip_version);

void ftrace_clear_pending_stack(struct ftrace_pending_stack *pending_stack);

void ftrace_set_message_common_fields(
	const struct ftrace_common_config *config,
	struct ftrace_pending_stack *pending_stack, struct trace_seq *seq,
	struct tep_event *trace_event, struct tep_record *rec,
	bt_field *context_field);

void ftrace_set_message_field(const struct ftrace_common_config *config,
							  struct trace_seq *seq,
							  struct tep_event *trace_event,
							  struct tep_record *rec,
							  struct tep_format_field *field,
							  bt_field *payload_field);

void ftrace_read_stack_field(struct tep_handle *tep,
							 struct tep_event *trace_event,
							 struct tep_record *rec, uint64_t **out_stack,
							 int *out_len);

#endif
