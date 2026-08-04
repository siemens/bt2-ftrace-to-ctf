/**
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef _BT_FTRACE_COMMON_H
#define _BT_FTRACE_COMMON_H

#include <babeltrace2/babeltrace.h>
#include <event-parse.h>
#include <glib.h>
#include <uuid.h>

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

#define FTRACE_STREAM_CLASS_UUID_NAMESPACE              \
	{                                                   \
		0x2d, 0x38, 0x0c, 0xd8, 0x5d, 0x7c, 0x4d, 0x2e, \
		0xb1, 0xdb, 0x5b, 0xd7, 0x67, 0x11, 0x57, 0x7d, \
	}

#define FTRACE_NAMESPACE "ftrace"
#define LTTNG_NAMESPACE "lttng.org,2009"

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

struct ftrace_trace_identity {
	const char *namespace;
	const char *name;
	const char *uid;
};

void ftrace_parse_common_params(const bt_value *params,
								struct ftrace_common_options *options);

void ftrace_common_opts_free(struct ftrace_common_options *options);

char *ftrace_format_stream_name(const char *path, uint64_t stream_class_id,
								uint64_t stream_id);

char *ftrace_format_port_name(const struct ftrace_trace_identity *identity,
							  uint64_t stream_class_id, uint64_t stream_id,
							  const char *fallback_path);

void ftrace_derive_trace_uid(uint64_t trace_id, char uid[UUID_STR_LEN]);

bt_event_class *
ftrace_create_event_class(bt_stream_class *stream_class,
						  struct tep_event *event,
						  const struct ftrace_common_config *config);

bt_stream_class *ftrace_create_stream_class(bt_trace_class *trace_class,
											bt_clock_class *clock_class,
											bt_bool supports_packets,
											uint64_t stream_class_id,
											const char *trace_uid,
											bt_bool lttng_format);

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
