/**
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "config.h"
#include "bt-ftrace-common.h"
#include "bt-ftrace-lttng-events.h"
#include "bt-ftrace-logging.h"
#include "bt-ftrace-sym-field.h"
#include "bt-ftrace-utils.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <uuid.h>

#define NS_PER_S (1000 * 1000 * 1000)

void ftrace_parse_common_params(const bt_value *params,
								struct ftrace_common_options *options)
{
	const bt_value *value;

	value = bt_value_map_borrow_entry_value_const(params, "lttng");
	if (value)
		options->config.lttng_format = bt_value_bool_get(value);
	value = bt_value_map_borrow_entry_value_const(params, "symbolize");
	if (value)
		options->config.symbolize_funcs = bt_value_bool_get(value);
	value = bt_value_map_borrow_entry_value_const(params, "callstack");
	if (value)
		options->config.with_callstacks = bt_value_bool_get(value);
	value = bt_value_map_borrow_entry_value_const(params, "clock-offset");
	if (value)
		options->clock_offset_ns = bt_value_integer_unsigned_get(value);
	value = bt_value_map_borrow_entry_value_const(params, "clock-uid");
	if (value)
		options->clock_uid = strdup(bt_value_string_get(value));
	value = bt_value_map_borrow_entry_value_const(params, "clock-namespace");
	if (value)
		options->clock_namespace = strdup(bt_value_string_get(value));
	value = bt_value_map_borrow_entry_value_const(params, "clock-name");
	if (value)
		options->clock_name = strdup(bt_value_string_get(value));
	value = bt_value_map_borrow_entry_value_const(params, "trace-name");
	if (value)
		options->trace_name = strdup(bt_value_string_get(value));
	value = bt_value_map_borrow_entry_value_const(params,
												  "trace-creation-datetime");
	if (value)
		options->trace_creation_datetime = strdup(bt_value_string_get(value));
}

void ftrace_common_opts_free(struct ftrace_common_options *options)
{
	free(options->clock_uid);
	free(options->clock_namespace);
	free(options->clock_name);
	free(options->trace_name);
	free(options->trace_creation_datetime);
	memset(options, 0, sizeof(*options));
}

char *ftrace_format_port_name(const struct ftrace_trace_identity *identity,
							  uint64_t stream_class_id, uint64_t stream_id,
							  const char *fallback_path)
{
	if (identity && identity->namespace && identity->name && identity->uid) {
		return g_strdup_printf(
			"{namespace: `%s`, name: `%s`, uid: `%s`} | %" PRIu64 " | %" PRIu64,
			identity->namespace, identity->name, identity->uid, stream_class_id,
			stream_id);
	}
	return g_strdup_printf("%s | %" PRIu64 " | %" PRIu64, fallback_path,
						   stream_class_id, stream_id);
}
void ftrace_derive_trace_uid(uint64_t trace_id, char uid[UUID_STR_LEN])
{
	static const uuid_t trace_namespace = FTRACE_TRACE_UUID_NAMESPACE;
	uuid_t trace_uuid;

	uuid_generate_md5(trace_uuid, trace_namespace, (const char *)&trace_id,
					  sizeof(trace_id));
	uuid_unparse(trace_uuid, uid);
}
static bt_field_class *
create_event_field_class(bt_trace_class *trace_class,
						 const struct tep_format_field *field,
						 const struct ftrace_common_config *config)
{
	const unsigned long flags = field->flags;
	bt_field_class *field_class = NULL;
	int field_size = field->size;

	if (flags & TEP_FIELD_IS_ARRAY && field->arraylen)
		field_size /= field->arraylen;
	if (flags & TEP_FIELD_IS_STRING) {
		field_class = bt_field_class_string_create(trace_class);
	} else if ((flags & TEP_FIELD_IS_DYNAMIC ||
				flags & TEP_FIELD_IS_RELATIVE) ||
			   field_size == 0 || field_size > 8) {
		BT_FTRACE_LOG_DEBUG(config->log_level, "   skip field %s, type: %s",
							field->name, field->type);
		return NULL;
	} else if (flags & TEP_FIELD_IS_SIGNED) {
		field_class = bt_field_class_integer_signed_create(trace_class);
		bt_field_class_integer_set_field_value_range(field_class,
													 field_size * 8);
	} else {
		field_class = bt_field_class_integer_unsigned_create(trace_class);
		bt_field_class_integer_set_field_value_range(field_class,
													 field_size * 8);
	}
	if (flags & TEP_FIELD_IS_POINTER &&
		bt_field_class_type_is(bt_field_class_get_type(field_class),
							   BT_FIELD_CLASS_TYPE_INTEGER))
		bt_field_class_integer_set_preferred_display_base(
			field_class,
			BT_FIELD_CLASS_INTEGER_PREFERRED_DISPLAY_BASE_HEXADECIMAL);
	return field_class;
}

static bt_field_class *create_callstack_field_class(bt_trace_class *trace_class,
													uint64_t mip_version,
													bt_bool symbolize)
{
	bt_field_class *elem_class;
	bt_field_class *field_class = NULL;
	if (symbolize) {
		elem_class = bt_field_class_string_create(trace_class);
	} else {
		elem_class = bt_field_class_integer_unsigned_create(trace_class);
		bt_field_class_integer_set_field_value_range(elem_class, 64);
		bt_field_class_integer_set_preferred_display_base(
			elem_class,
			BT_FIELD_CLASS_INTEGER_PREFERRED_DISPLAY_BASE_HEXADECIMAL);
	}
	if (mip_version == 0)
		field_class =
			bt_field_class_array_dynamic_create(trace_class, elem_class, NULL);
#if HAS_BT2_NEW_DYNAMIC_FIELD_API
	else
		field_class =
			bt_field_class_array_dynamic_without_length_field_location_create(
				trace_class, elem_class);
#endif
	bt_field_class_put_ref(elem_class);
	return field_class;
}

static void append_common_context_fields(
	bt_trace_class *trace_class, bt_field_class *context_field_class,
	struct tep_event *event, const struct ftrace_common_config *config)
{
	bt_field_class *field_class;
	const char *field_name;
	field_class = bt_field_class_integer_signed_create(trace_class);
	bt_field_class_integer_set_field_value_range(field_class, 32);
	field_name = config->lttng_format ?
					 lttng_get_field_name_from_event(event, "common_pid") :
					 "common_pid";
	bt_field_class_structure_append_member(context_field_class, field_name,
										   field_class);
	bt_field_class_put_ref(field_class);
	field_class = bt_field_class_string_create(trace_class);
	field_name = config->lttng_format ?
					 lttng_get_field_name_from_event(event, "task") :
					 "task";
	bt_field_class_structure_append_member(context_field_class, field_name,
										   field_class);
	bt_field_class_put_ref(field_class);
	field_class = bt_field_class_string_create(trace_class);
	bt_field_class_structure_append_member(context_field_class, "latency",
										   field_class);
	bt_field_class_put_ref(field_class);
	if (!config->with_callstacks)
		return;
	field_class = create_callstack_field_class(trace_class, config->mip_version,
											   config->symbolize_funcs);
	field_name = config->lttng_format ?
					 lttng_get_field_name_from_event(event, "kernel_stack") :
					 "kernel_stack";
	bt_field_class_structure_append_member(context_field_class, field_name,
										   field_class);
	bt_field_class_put_ref(field_class);
	field_class =
		create_callstack_field_class(trace_class, config->mip_version, false);
	field_name = config->lttng_format ?
					 lttng_get_field_name_from_event(event, "user_stack") :
					 "user_stack";
	bt_field_class_structure_append_member(context_field_class, field_name,
										   field_class);
	bt_field_class_put_ref(field_class);
}

bt_event_class *
ftrace_create_event_class(bt_stream_class *stream_class,
						  struct tep_event *event,
						  const struct ftrace_common_config *config)
{
	char name[128];
	bt_trace_class *trace_class =
		bt_stream_class_borrow_trace_class(stream_class);
	bt_event_class *event_class = bt_event_class_create(stream_class);
	bt_field_class *payload = bt_field_class_structure_create(trace_class);
	bt_field_class *context = bt_field_class_structure_create(trace_class);
	struct tep_format_field **fields;
	if (config->lttng_format)
		snprintf(name, sizeof(name), "%s",
				 lttng_get_event_name_from_event(event));
	else
		snprintf(name, sizeof(name), "%s:%s", event->system, event->name);
	bt_event_class_set_name(event_class, name);
	BT_FTRACE_LOG_INFO(config->log_level, "create event %s", name);
	append_common_context_fields(trace_class, context, event, config);
	fields = tep_event_fields(event);
	for (int i = 0; fields[i]; i++) {
		const char *in_name = fields[i]->name;
		const char *out_name =
			config->lttng_format ?
				lttng_get_field_name_from_event(event, in_name) :
				in_name;
		bt_field_class *field_class;
		if (config->lttng_format && event_system_is("syscalls", event) &&
			strcmp(in_name, "__syscall_nr") == 0)
			continue;
		BT_FTRACE_LOG_DEBUG(config->log_level, "  %s:%s:%d:%d|%d", in_name,
							fields[i]->type, fields[i]->offset, fields[i]->size,
							fields[i]->arraylen);
		if (config->symbolize_funcs && event_field_is_symbolic(event, in_name))
			field_class = bt_field_class_string_create(trace_class);
		else if (fields[i]->flags & TEP_FIELD_IS_STRING)
			field_class =
				create_event_field_class(trace_class, fields[i], config);
		else if (fields[i]->flags & TEP_FIELD_IS_ARRAY) {
			bt_field_class *member =
				create_event_field_class(trace_class, fields[i], config);
			if (!member)
				continue;
			field_class = bt_field_class_array_static_create(
				trace_class, member, fields[i]->arraylen);
			bt_field_class_put_ref(member);
		} else
			field_class =
				create_event_field_class(trace_class, fields[i], config);
		if (!field_class)
			continue;
		if (bt_field_class_structure_borrow_member_by_name(payload, out_name)) {
			BT_FTRACE_LOG_WARNING(config->log_level,
								  "   skip duplicated field %s, type: %s on %s",
								  out_name, fields[i]->type, name);
		} else {
			bt_field_class_structure_append_member(payload, out_name,
												   field_class);
		}
		bt_field_class_put_ref(field_class);
	}
	free(fields);
	bt_event_class_set_payload_field_class(event_class, payload);
	bt_event_class_set_specific_context_field_class(event_class, context);
	bt_field_class_put_ref(payload);
	bt_field_class_put_ref(context);
	return event_class;
}

bt_stream_class *ftrace_create_stream_class(bt_trace_class *trace_class,
											bt_clock_class *clock_class,
											bt_bool supports_packets)
{
	bt_trace_class_set_assigns_automatic_stream_class_id(trace_class, BT_FALSE);
	bt_stream_class *stream_class =
		bt_stream_class_create_with_id(trace_class, 0);
	bt_stream_class_set_assigns_automatic_stream_id(stream_class, BT_FALSE);

	bt_stream_class_set_name(stream_class, "ftrace-stream");
	bt_stream_class_set_default_clock_class(stream_class, clock_class);
	bt_stream_class_set_supports_discarded_events(stream_class, BT_TRUE,
												  BT_TRUE);
	if (supports_packets) {
		bt_field_class *packet_context =
			bt_field_class_structure_create(trace_class);
		bt_field_class *cpu_id =
			bt_field_class_integer_unsigned_create(trace_class);
		bt_field_class_integer_set_field_value_range(cpu_id, 32);
		bt_field_class_structure_append_member(packet_context, "cpu_id",
											   cpu_id);
		bt_stream_class_set_supports_packets(stream_class, BT_TRUE, BT_TRUE,
											 BT_TRUE);
		bt_stream_class_set_supports_discarded_packets(stream_class, BT_TRUE,
													   BT_TRUE);
		bt_stream_class_set_packet_context_field_class(stream_class,
													   packet_context);
		bt_field_class_put_ref(cpu_id);
		bt_field_class_put_ref(packet_context);
	}
	return stream_class;
}

GHashTable *
ftrace_create_event_classes(struct tep_handle *tep,
							bt_stream_class *stream_class,
							const struct ftrace_common_config *config)
{
	GHashTable *event_classes =
		g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
							  (GDestroyNotify)bt_event_class_put_ref);
	struct tep_event **events = tep_list_events(tep, TEP_EVENT_SORT_ID);

	if (!events)
		return event_classes;
	for (int i = 0; events[i]; i++) {
		bt_event_class *event_class =
			ftrace_create_event_class(stream_class, events[i], config);
		g_hash_table_insert(event_classes, (gpointer)(uintptr_t)events[i]->id,
							event_class);
	}
	return event_classes;
}

void ftrace_set_trace_environment(
	bt_trace *trace, const struct ftrace_common_config *config,
	const char *sysname, const char *kernel_release, const char *hostname,
	const char *trace_name, const char *trace_creation_datetime,
	int tracer_version_major, int tracer_version_minor)
{
	if (trace_name) {
		bt_trace_set_name(trace, trace_name);
		bt_trace_set_environment_entry_string(trace, "trace_name", trace_name);
	}
	bt_trace_set_environment_entry_string(trace, "domain", "kernel");
	bt_trace_set_environment_entry_string(trace, "sysname", sysname);
	if (kernel_release)
		bt_trace_set_environment_entry_string(trace, "kernel_release",
											  kernel_release);
	bt_trace_set_environment_entry_string(trace, "trace_buffering_scheme",
										  "global");
	bt_trace_set_environment_entry_string(
		trace, "tracer_name",
		config->lttng_format ? "lttng-modules" : "ftrace");
	bt_trace_set_environment_entry_integer(
		trace, "tracer_major",
		config->lttng_format ? LTTNG_VERSION_MAJOR : tracer_version_major);
	bt_trace_set_environment_entry_integer(
		trace, "tracer_minor",
		config->lttng_format ? LTTNG_VERSION_MINOR : tracer_version_minor);
	if (hostname)
		bt_trace_set_environment_entry_string(trace, "hostname", hostname);
	if (trace_creation_datetime)
		bt_trace_set_environment_entry_string(trace, "trace_creation_datetime",
											  trace_creation_datetime);
}

void ftrace_configure_clock(bt_clock_class *clock_class,
							const char *input_clock_name,
							const char *clock_name_override,
							uint64_t clock_offset_ns, const char *clock_uid,
							const char *clock_namespace, uint64_t mip_version)
{
	if (clock_name_override) {
		bt_clock_class_set_name(clock_class, clock_name_override);
	} else if (strcmp(input_clock_name, "mono") == 0 ||
			   strcmp(input_clock_name, "mono_raw") == 0) {
		bt_clock_class_set_name(clock_class, "monotonic");
		bt_clock_class_set_description(clock_class, "Monotonic Clock");
	} else {
		bt_clock_class_set_name(clock_class, input_clock_name);
	}
	if (clock_offset_ns) {
		bt_clock_class_set_offset(clock_class, clock_offset_ns / NS_PER_S,
								  clock_offset_ns % NS_PER_S);
		bt_clock_class_origin_is_unix_epoch(clock_class);
	} else {
#if HAS_BT2_CLOCK_UNKNOWN
		bt_clock_class_set_origin_unknown(clock_class);
#endif
	}
	if (!clock_uid)
		return;
	if (mip_version == 0) {
		uuid_t clock_uuid;
		if (uuid_parse(clock_uid, clock_uuid) == 0)
			bt_clock_class_set_uuid(clock_class, clock_uuid);
		return;
	}
#if HAS_BT2_CLOCK_UID
	bt_clock_class_set_uid(clock_class, clock_uid);
#endif
#if HAS_BT2_CLOCK_NAMESPACE
	if (clock_namespace)
		bt_clock_class_set_namespace(clock_class, clock_namespace);
#endif
}

void ftrace_clear_pending_stack(struct ftrace_pending_stack *pending_stack)
{
	free(pending_stack->kernel_stack);
	pending_stack->kernel_stack = NULL;
	pending_stack->klen = 0;
	free(pending_stack->user_stack);
	pending_stack->user_stack = NULL;
	pending_stack->ulen = 0;
}

static int64_t convert_to_signed(uint64_t val, uint64_t bits)
{
	const uint64_t sign_bit = UINT64_C(1) << (bits - 1);
	const uint64_t full_range = UINT64_C(1) << bits;
	return val & sign_bit ? (int64_t)(val - full_range) : (int64_t)val;
}

static void set_field_value(const struct ftrace_common_config *config,
							struct tep_format_field *field,
							const char *field_name, bt_field *data_field,
							const bt_field_class *data_class,
							bt_field_class_type data_class_type, void *data,
							int len)
{
	if (bt_field_class_type_is(data_class_type, BT_FIELD_CLASS_TYPE_STRING))
		bt_field_string_set_value(data_field, data);
	else if (bt_field_class_type_is(data_class_type,
									BT_FIELD_CLASS_TYPE_SIGNED_INTEGER)) {
		int64_t val = convert_to_signed(
			tep_read_number(field->event->tep, data, len),
			bt_field_class_integer_get_field_value_range(data_class));
		if (config->lttng_format)
			val = lttng_get_field_val_from_event_signed(field->event,
														field_name, val);
		bt_field_integer_signed_set_value(data_field, val);
	} else if (bt_field_class_type_is(data_class_type,
									  BT_FIELD_CLASS_TYPE_UNSIGNED_INTEGER)) {
		uint64_t val = tep_read_number(field->event->tep, data, len);
		if (config->lttng_format)
			val = lttng_get_field_val_from_event_unsigned(field->event,
														  field_name, val);
		bt_field_integer_unsigned_set_value(data_field, val);
	}
}

void ftrace_set_message_common_fields(
	const struct ftrace_common_config *config,
	struct ftrace_pending_stack *pending_stack, struct trace_seq *seq,
	struct tep_event *trace_event, struct tep_record *rec, bt_field *context)
{
	const bt_bool lttng = config->lttng_format;
	const int pid = tep_data_pid(trace_event->tep, rec);
	const char *name =
		lttng ? lttng_get_field_name_from_event(trace_event, "common_pid") :
				"common_pid";
	bt_field *field =
		bt_field_structure_borrow_member_field_by_name(context, name);
	bt_field_integer_signed_set_value(field, pid);
	name = lttng ? lttng_get_field_name_from_event(trace_event, "task") :
				   "task";
	field = bt_field_structure_borrow_member_field_by_name(context, name);
	bt_field_string_set_value(field,
							  tep_data_comm_from_pid(trace_event->tep, pid));
	field = bt_field_structure_borrow_member_field_by_name(context, "latency");
	trace_seq_reset(seq);
	tep_print_event(trace_event->tep, seq, rec, "%s", TEP_PRINT_LATENCY);
	trace_seq_terminate(seq);
	bt_field_string_set_value(field, seq->buffer);
	if (config->with_callstacks) {
		const char *stack_name =
			lttng ?
				lttng_get_field_name_from_event(trace_event, "kernel_stack") :
				"kernel_stack";
		bt_field *array =
			bt_field_structure_borrow_member_field_by_name(context, stack_name);
		bt_field_array_dynamic_set_length(array, pending_stack->klen);
		for (int i = 0; i < pending_stack->klen; i++) {
			bt_field *element =
				bt_field_array_borrow_element_field_by_index(array, i);
			if (config->symbolize_funcs) {
				format_func_addr(trace_event->tep, seq,
								 pending_stack->kernel_stack[i]);
				bt_field_string_set_value(element, seq->buffer);
			} else
				bt_field_integer_unsigned_set_value(
					element, pending_stack->kernel_stack[i]);
		}
		stack_name =
			lttng ? lttng_get_field_name_from_event(trace_event, "user_stack") :
					"user_stack";
		array =
			bt_field_structure_borrow_member_field_by_name(context, stack_name);
		bt_field_array_dynamic_set_length(array, pending_stack->ulen);
		for (int i = 0; i < pending_stack->ulen; i++)
			bt_field_integer_unsigned_set_value(
				bt_field_array_borrow_element_field_by_index(array, i),
				pending_stack->user_stack[i]);
	}
	ftrace_clear_pending_stack(pending_stack);
}

void ftrace_set_message_field(const struct ftrace_common_config *config,
							  struct trace_seq *seq,
							  struct tep_event *trace_event,
							  struct tep_record *rec,
							  struct tep_format_field *field, bt_field *payload)
{
	const char *name =
		config->lttng_format ?
			lttng_get_field_name_from_event(trace_event, field->name) :
			field->name;
	bt_field *data_field =
		bt_field_structure_borrow_member_field_by_name(payload, name);
	int len = 0;
	uint8_t *raw;
	if (!data_field) {
		BT_FTRACE_LOG_DEBUG(config->log_level,
							"skip unknown field \"%s\" on %s:%s", name,
							trace_event->system, trace_event->name);
		return;
	}
	if (bt_field_class_type_is(bt_field_get_class_type(data_field),
							   BT_FIELD_CLASS_TYPE_STATIC_ARRAY)) {
		const bt_field_class *member =
			bt_field_class_array_borrow_element_field_class_const(
				bt_field_borrow_class_const(data_field));
		const int items = field->arraylen;
		raw = tep_get_field_raw(NULL, trace_event, field->name, rec, &len, 0);
		for (int i = 0; i < items; i++)
			set_field_value(
				config, field, name,
				bt_field_array_borrow_element_field_by_index(data_field, i),
				member, bt_field_class_get_type(member),
				raw + i * (len / items), len / items);
	} else if (config->symbolize_funcs &&
			   event_field_is_symbolic(trace_event, field->name)) {
		event_set_symbolic_field(field->event, rec, seq, data_field,
								 field->name);
	} else {
		raw = tep_get_field_raw(NULL, trace_event, field->name, rec, &len, 0);
		set_field_value(config, field, name, data_field,
						bt_field_borrow_class_const(data_field),
						bt_field_get_class_type(data_field), raw, len);
	}
}

void ftrace_read_stack_field(struct tep_handle *tep,
							 struct tep_event *trace_event,
							 struct tep_record *rec, uint64_t **out_stack,
							 int *out_len)
{
	int len = 0;
	uint8_t *raw =
		(uint8_t *)tep_get_field_raw(NULL, trace_event, "caller", rec, &len, 0);
	int count = len / sizeof(uint64_t);
	free(*out_stack);
	*out_stack = malloc(count * sizeof(uint64_t));
	for (int i = 0; i < count; i++)
		(*out_stack)[i] =
			tep_read_number(tep, raw + i * sizeof(uint64_t), sizeof(uint64_t));
	while (count > 0 && (*out_stack)[count - 1] == 0)
		count--;
	*out_len = count;
}
