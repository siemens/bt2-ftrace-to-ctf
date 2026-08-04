/**
 * SPDX-FileCopyrightText: (C) 2026 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Live ftrace source component for babeltrace (source.ftrace.live).
 */

#include "config.h"
#include "bt-ftrace-source-live.h"
#include "bt-ftrace-common.h"
#include "bt-ftrace-logging.h"

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tracefs.h>
#include <kbuffer.h>
#include <sys/utsname.h>
#include <uuid.h>

struct ftrace_live_port {
	int cpu_id;
	bt_stream *stream;
};

enum ftrace_live_iterator_state {
	FTRACE_LIVE_ITERATOR_STATE_STREAM_BEGINNING,
	FTRACE_LIVE_ITERATOR_STATE_EVENT,
	FTRACE_LIVE_ITERATOR_STATE_STREAM_ENDING,
	FTRACE_LIVE_ITERATOR_STATE_ENDED,
};

struct ftrace_live_iterator {
	struct ftrace_live *live;
	struct ftrace_live_port *port;
	struct tracefs_cpu *cpu;
	struct kbuffer *buffer;
	struct tep_record record;
	bool record_ready;
	bool trace_flushed;
	bt_packet *packet;
	bool packet_end_pending;
	long long events_discarded;
	uint64_t last_record_ts;
	struct ftrace_pending_stack pending_stack;
	struct trace_seq seq;
	enum ftrace_live_iterator_state state;
};

struct ftrace_live {
	bt_logging_level log_level;
	struct tracefs_instance *instance;
	struct tep_handle *tep;
	char *tracing_dir;
	char *clock_name;
	char trace_uid[UUID_STR_LEN];
	struct utsname system_info;
	struct ftrace_common_options options;
	GHashTable *event_classes;
	bt_stream_class *stream_class;
	bt_trace *trace;
	struct ftrace_live_port *ports;
	unsigned int nb_ports;
};

static bt_message *
create_live_message(struct ftrace_live_iterator *iterator,
					bt_self_message_iterator *self_message_iterator)
{
	bt_stream *stream = iterator->port->stream;
	struct tep_event *trace_event;
	struct tep_format_field **fields;
	bt_message *message;

	if (iterator->state == FTRACE_LIVE_ITERATOR_STATE_STREAM_BEGINNING) {
		iterator->state = FTRACE_LIVE_ITERATOR_STATE_EVENT;
		return bt_message_stream_beginning_create(self_message_iterator,
												  stream);
	}
	if (iterator->packet &&
		(iterator->events_discarded || iterator->packet_end_pending ||
		 iterator->state == FTRACE_LIVE_ITERATOR_STATE_STREAM_ENDING)) {
		message = bt_message_packet_end_create_with_default_clock_snapshot(
			self_message_iterator, iterator->packet, iterator->last_record_ts);
		BT_PACKET_PUT_REF_AND_RESET(iterator->packet);
		iterator->packet_end_pending = false;
		return message;
	}
	if (iterator->state == FTRACE_LIVE_ITERATOR_STATE_STREAM_ENDING) {
		iterator->state = FTRACE_LIVE_ITERATOR_STATE_ENDED;
		return bt_message_stream_end_create(self_message_iterator, stream);
	}
	if (iterator->state == FTRACE_LIVE_ITERATOR_STATE_ENDED)
		return NULL;
	if (iterator->events_discarded) {
		message =
			bt_message_discarded_events_create_with_default_clock_snapshots(
				self_message_iterator, stream, iterator->last_record_ts,
				iterator->record.ts);
		if (iterator->events_discarded != -1)
			bt_message_discarded_events_set_count(message,
												  iterator->events_discarded);
		iterator->events_discarded = 0;
		return message;
	}
	if (!iterator->packet) {
		bt_field *context;
		bt_field *cpu_id;

		iterator->packet = bt_packet_create(stream);
		context = bt_packet_borrow_context_field(iterator->packet);
		cpu_id =
			bt_field_structure_borrow_member_field_by_name(context, "cpu_id");
		bt_field_integer_unsigned_set_value(cpu_id, iterator->port->cpu_id);
		return bt_message_packet_beginning_create_with_default_clock_snapshot(
			self_message_iterator, iterator->packet, iterator->record.ts);
	}
	trace_event =
		tep_find_event_by_record(iterator->live->tep, &iterator->record);
	if (!trace_event) {
		BT_FTRACE_LOG_WARNING(iterator->live->log_level,
							  "skip unknown live ftrace event on CPU %d",
							  iterator->port->cpu_id);
		iterator->record_ready = false;
		iterator->last_record_ts = iterator->record.ts;
		return NULL;
	}
	if (strcmp(trace_event->name, "kernel_stack") == 0) {
		ftrace_read_stack_field(iterator->live->tep, trace_event,
								&iterator->record,
								&iterator->pending_stack.kernel_stack,
								&iterator->pending_stack.klen);
		iterator->record_ready = false;
		iterator->last_record_ts = iterator->record.ts;
		return NULL;
	}
	if (strcmp(trace_event->name, "user_stack") == 0) {
		ftrace_read_stack_field(iterator->live->tep, trace_event,
								&iterator->record,
								&iterator->pending_stack.user_stack,
								&iterator->pending_stack.ulen);
		iterator->record_ready = false;
		iterator->last_record_ts = iterator->record.ts;
		return NULL;
	}
	bt_event_class *event_class =
		g_hash_table_lookup(iterator->live->event_classes,
							(gconstpointer)(uintptr_t)trace_event->id);
	if (!event_class) {
		iterator->record_ready = false;
		iterator->last_record_ts = iterator->record.ts;
		return NULL;
	}
	message = bt_message_event_create_with_packet_and_default_clock_snapshot(
		self_message_iterator, event_class, iterator->packet,
		iterator->record.ts);
	bt_event *event = bt_message_event_borrow_event(message);
	bt_field *payload = bt_event_borrow_payload_field(event);
	bt_field *context = bt_event_borrow_specific_context_field(event);
	ftrace_set_message_common_fields(&iterator->live->options.config,
									 &iterator->pending_stack, &iterator->seq,
									 trace_event, &iterator->record, context);
	fields = tep_event_fields(trace_event);
	for (int i = 0; fields[i]; i++)
		ftrace_set_message_field(&iterator->live->options.config,
								 &iterator->seq, trace_event, &iterator->record,
								 fields[i], payload);
	free(fields);
	iterator->record_ready = false;
	iterator->last_record_ts = iterator->record.ts;
	return message;
}

/*
 * Accumulate the events the kernel dropped, as we might not be able to report
 * them before the next sub-buffer is loaded. A negative count denotes an
 * unknown number of dropped events, which is preserved.
 */
static void add_discarded_events(struct ftrace_live_iterator *iterator,
								 int missed_events)
{
	if (!missed_events)
		return;
	if (missed_events < 0 || iterator->events_discarded < 0)
		iterator->events_discarded = -1;
	else
		iterator->events_discarded += missed_events;
}

static bool read_live_buffer(struct ftrace_live_iterator *iterator)
{
	void *data;

	if (!(data = kbuffer_read_event(iterator->buffer, &iterator->record.ts)))
		return false;
	iterator->record.data = data;
	iterator->record.size = kbuffer_event_size(iterator->buffer);
	iterator->record.record_size = kbuffer_curr_size(iterator->buffer);
	iterator->record.cpu = iterator->port->cpu_id;
	iterator->record.missed_events = 0;
	kbuffer_next_event(iterator->buffer, NULL);
	iterator->record_ready = true;
	return true;
}

static bool read_live_record(struct ftrace_live_iterator *iterator)
{
	while (!iterator->buffer || !read_live_buffer(iterator)) {
		if (iterator->buffer && iterator->packet)
			iterator->packet_end_pending = true;
		iterator->buffer = tracefs_cpu_read_buf(iterator->cpu, true);
		if (!iterator->buffer)
			return false;
		/* the dropped events are reported per sub-buffer */
		add_discarded_events(iterator, kbuffer_missed_events(iterator->buffer));
	}
	return true;
}

/*
 * Once tracing is off, tracefs_cpu_read_buf() only returns complete
 * sub-buffers, leaving the events of the currently written sub-buffer behind.
 * Flush it once so those trailing events are not lost before we end the stream.
 * Returns true if a record became available.
 */
static bool flush_live_record(struct ftrace_live_iterator *iterator)
{
	if (iterator->trace_flushed)
		return false;
	iterator->trace_flushed = true;
	if (iterator->buffer && iterator->packet)
		iterator->packet_end_pending = true;
	iterator->buffer = tracefs_cpu_flush_buf(iterator->cpu);
	if (!iterator->buffer)
		return false;
	/* the dropped events are reported per sub-buffer */
	add_discarded_events(iterator, kbuffer_missed_events(iterator->buffer));
	return read_live_buffer(iterator);
}

static void ftrace_live_free(struct ftrace_live *live)
{
	if (!live)
		return;
	tep_free(live->tep);
	tracefs_instance_free(live->instance);
	if (live->event_classes)
		g_hash_table_unref(live->event_classes);
	BT_STREAM_CLASS_PUT_REF_AND_RESET(live->stream_class);
	BT_TRACE_PUT_REF_AND_RESET(live->trace);
	for (unsigned int i = 0; i < live->nb_ports; i++)
		BT_STREAM_PUT_REF_AND_RESET(live->ports[i].stream);
	free(live->ports);
	free(live->tracing_dir);
	free(live->clock_name);
	ftrace_common_opts_free(&live->options);
	free(live);
}

struct tracefs_instance *ftrace_live_open_existing_instance(const char *path,
															char **tracing_dir)
{
	char *normalized_path = g_canonicalize_filename(path, NULL);
	char *parent = g_path_get_dirname(normalized_path);
	char *parent_name = g_path_get_basename(parent);
	struct tracefs_instance *instance;
	char *dir;

	if (strcmp(parent_name, "instances") == 0) {
		char *instance_name = g_path_get_basename(normalized_path);
		dir = g_path_get_dirname(parent);
		instance = tracefs_instance_alloc(dir, instance_name);
		g_free(instance_name);
	} else {
		dir = g_strdup(normalized_path);
		instance = tracefs_instance_alloc(dir, NULL);
	}
	/* hand out a libc allocation, as the callers release it with free() */
	*tracing_dir = strdup(dir);
	g_free(dir);
	g_free(parent_name);
	g_free(parent);
	g_free(normalized_path);
	return instance;
}

char *ftrace_live_derive_uid(void)
{
	char *boot_id = NULL;

	if (!g_file_get_contents("/proc/sys/kernel/random/boot_id", &boot_id, NULL,
							 NULL)) {
		return NULL;
	}
	g_strchomp(boot_id);
	return boot_id;
}

static int ftrace_live_derive_clock_uid(struct ftrace_live *live,
										const char *uid_seed)
{
	static const uuid_t clock_namespace = FTRACE_CLOCK_UUID_NAMESPACE;
	char *seed;
	uuid_t clock_uuid;
	char uid[UUID_STR_LEN];

	if (live->options.clock_uid)
		return 0;
	seed = g_strdup_printf("%s:%s", live->clock_name, uid_seed);
	uuid_generate_md5(clock_uuid, clock_namespace, seed, strlen(seed));
	uuid_unparse(clock_uuid, uid);
	g_free(seed);
	live->options.clock_uid = strdup(uid);
	live->options.clock_namespace = strdup(FTRACE_NAMESPACE);
	return live->options.clock_uid && live->options.clock_namespace ? 0 : -1;
}

int ftrace_live_derive_trace_uid(const char *tracing_dir, const char *uid_seed,
								 char uid[UUID_STR_LEN])
{
	static const uuid_t trace_namespace = FTRACE_TRACE_UUID_NAMESPACE;
	char *seed = g_strdup_printf("%s:%s", tracing_dir, uid_seed);
	uuid_t trace_uuid;

	uuid_generate_md5(trace_uuid, trace_namespace, seed, strlen(seed));
	uuid_unparse(trace_uuid, uid);
	g_free(seed);
	return 0;
}

static bool ftrace_live_set_creation_datetime(struct ftrace_live *live)
{
	GDateTime *now;
	char *formatted;

	if (live->options.trace_creation_datetime)
		return true;
	now = g_date_time_new_now_local();
	if (!now)
		return false;
	formatted = g_date_time_format(now, "%Y%m%dT%H%M%S%z");
	g_date_time_unref(now);
	if (!formatted)
		return false;
	/* the option strings are released with free() */
	live->options.trace_creation_datetime = strdup(formatted);
	g_free(formatted);
	return live->options.trace_creation_datetime != NULL;
}
static int
create_metadata_and_ports(bt_self_component_source *self_component_source,
						  struct ftrace_live *live)
{
	bt_self_component *self_component =
		bt_self_component_source_as_self_component(self_component_source);
	bt_trace_class *trace_class = bt_trace_class_create(self_component);
	bt_clock_class *clock_class = bt_clock_class_create(self_component);
	const int ncpus = tep_get_cpus(live->tep);

	live->options.config.mip_version =
		bt_self_component_get_graph_mip_version(self_component);
	ftrace_configure_clock(
		clock_class, live->clock_name, live->options.clock_name,
		live->options.clock_offset_ns, live->options.clock_uid,
		live->options.clock_namespace, live->options.config.mip_version);
	live->stream_class =
		ftrace_create_stream_class(trace_class, clock_class, BT_TRUE);
	live->event_classes = ftrace_create_event_classes(
		live->tep, live->stream_class, &live->options.config);
	live->trace = bt_trace_create(trace_class);
	bt_trace_set_name(live->trace,
					  live->options.trace_name ? live->options.trace_name : "");
	if (live->options.config.mip_version == 0) {
		uuid_t trace_uuid;

		uuid_parse(live->trace_uid, trace_uuid);
		bt_trace_set_uuid(live->trace, trace_uuid);
	} else {
#if HAS_BT2_TRACE_UID
		bt_trace_set_uid(live->trace, live->trace_uid);
#endif
#if HAS_BT2_TRACE_NAMESPACE
		bt_trace_set_namespace(live->trace, FTRACE_TRACE_NAMESPACE);
#endif
	}
	ftrace_set_trace_environment(
		live->trace, &live->options.config, live->system_info.sysname,
		live->system_info.release, live->system_info.nodename,
		live->options.trace_name, live->options.trace_creation_datetime,
		FT_VERSION_MAJOR, FT_VERSION_MINOR);
	live->ports = calloc(ncpus, sizeof(*live->ports));
	if (!live->ports) {
		bt_clock_class_put_ref(clock_class);
		bt_trace_class_put_ref(trace_class);
		return -1;
	}
	live->nb_ports = ncpus;
	for (int cpu = 0; cpu < ncpus; cpu++) {
		char *stream_name;
		const struct ftrace_trace_identity identity = {
			.namespace = FTRACE_TRACE_NAMESPACE,
			.name = live->options.trace_name ? live->options.trace_name : "",
			.uid = live->trace_uid,
		};
		live->ports[cpu].cpu_id = cpu;
		live->ports[cpu].stream =
			bt_stream_create_with_id(live->stream_class, live->trace, cpu);
		stream_name =
			ftrace_format_port_name(&identity, 0, cpu, live->tracing_dir);
		bt_stream_set_name(live->ports[cpu].stream, stream_name);
		bt_self_component_source_add_output_port(
			self_component_source, stream_name, &live->ports[cpu], NULL);
		g_free(stream_name);
	}
	bt_clock_class_put_ref(clock_class);
	bt_trace_class_put_ref(trace_class);
	return 0;
}

bt_component_class_initialize_method_status
ftrace_live_initialize(bt_self_component_source *self_component_source,
					   bt_self_component_source_configuration *configuration,
					   const bt_value *params, void *initialize_method_data)
{
	bt_self_component *self_component =
		bt_self_component_source_as_self_component(self_component_source);
	struct ftrace_live *live = calloc(1, sizeof(*live));
	const bt_value *inputs;
	const bt_value *path_value;
	const char *path;

	if (!live)
		return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_MEMORY_ERROR;
	live->log_level =
		bt_component_get_logging_level(bt_component_source_as_component_const(
			bt_self_component_source_as_component_source(
				self_component_source)));
	bt_self_component_set_data(self_component, live);
	live->options.config.log_level = live->log_level;
	if (uname(&live->system_info) < 0) {
		BT_FTRACE_LOG_ERROR(live->log_level,
							"cannot read kernel system information");
		goto error;
	}
	if (!params) {
		BT_FTRACE_LOG_ERROR(live->log_level,
							"missing mandatory inputs parameter");
		goto error;
	}
	inputs = bt_value_map_borrow_entry_value_const(params, "inputs");
	if (!inputs || !bt_value_is_array(inputs) ||
		bt_value_array_get_length(inputs) != 1) {
		BT_FTRACE_LOG_ERROR(live->log_level,
							"mandatory inputs parameter must contain one path");
		goto error;
	}
	path_value = bt_value_array_borrow_element_by_index_const(inputs, 0);
	if (!bt_value_is_string(path_value)) {
		BT_FTRACE_LOG_ERROR(live->log_level, "input path must be a string");
		goto error;
	}
	path = bt_value_string_get(path_value);
	ftrace_parse_common_params(params, &live->options);
	if (!ftrace_live_set_creation_datetime(live))
		BT_FTRACE_LOG_WARNING(live->log_level,
							  "cannot create trace creation datetime");
	live->instance =
		ftrace_live_open_existing_instance(path, &live->tracing_dir);
	if (!live->instance) {
		BT_FTRACE_LOG_ERROR(live->log_level,
							"cannot open existing tracefs instance %s", path);
		goto error;
	}
	live->tep = tracefs_local_events(live->tracing_dir);
	if (!live->tep || tracefs_load_headers(live->tracing_dir, live->tep) < 0) {
		BT_FTRACE_LOG_ERROR(live->log_level,
							"cannot load tracefs metadata from %s", path);
		goto error;
	}
	live->clock_name = tracefs_get_clock(live->instance);
	if (!live->clock_name) {
		BT_FTRACE_LOG_ERROR(live->log_level,
							"cannot read configured clock from %s", path);
		goto error;
	}
	char *uid_seed = ftrace_live_derive_uid();
	if (!uid_seed) {
		BT_FTRACE_LOG_ERROR(live->log_level, "cannot read the trace UID seed");
		goto error;
	}
	if (ftrace_live_derive_clock_uid(live, uid_seed) < 0) {
		BT_FTRACE_LOG_ERROR(live->log_level, "cannot derive a clock UID");
		g_free(uid_seed);
		goto error;
	}
	if (ftrace_live_derive_trace_uid(live->tracing_dir, uid_seed,
									 live->trace_uid) < 0) {
		BT_FTRACE_LOG_ERROR(live->log_level, "cannot derive a trace UID");
		g_free(uid_seed);
		goto error;
	}
	g_free(uid_seed);
	if (create_metadata_and_ports(self_component_source, live) < 0)
		goto error;
	return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_OK;

error:
	bt_self_component_set_data(self_component, NULL);
	ftrace_live_free(live);
	return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
}

void ftrace_live_finalize(bt_self_component_source *self_component_source)
{
	struct ftrace_live *live = bt_self_component_get_data(
		bt_self_component_source_as_self_component(self_component_source));
	ftrace_live_free(live);
}

bt_message_iterator_class_initialize_method_status
ftrace_live_message_iterator_initialize(
	bt_self_message_iterator *self_message_iterator,
	bt_self_message_iterator_configuration *configuration,
	bt_self_component_port_output *self_port)
{
	struct ftrace_live_iterator *iterator = calloc(1, sizeof(*iterator));

	if (!iterator)
		return BT_MESSAGE_ITERATOR_CLASS_INITIALIZE_METHOD_STATUS_MEMORY_ERROR;
	iterator->live = bt_self_component_get_data(
		bt_self_message_iterator_borrow_component(self_message_iterator));
	iterator->port = bt_self_component_port_get_data(
		bt_self_component_port_output_as_self_component_port(self_port));
	iterator->cpu = tracefs_cpu_open(iterator->live->instance,
									 iterator->port->cpu_id, true);
	if (!iterator->cpu) {
		BT_FTRACE_LOG_ERROR(iterator->live->log_level,
							"cannot open CPU %d trace pipe",
							iterator->port->cpu_id);
		free(iterator);
		return BT_MESSAGE_ITERATOR_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
	}
	trace_seq_init(&iterator->seq);
	iterator->state = FTRACE_LIVE_ITERATOR_STATE_STREAM_BEGINNING;
	bt_self_message_iterator_configuration_set_can_seek_forward(configuration,
																BT_FALSE);
	bt_self_message_iterator_set_data(self_message_iterator, iterator);
	return BT_MESSAGE_ITERATOR_CLASS_INITIALIZE_METHOD_STATUS_OK;
}

void ftrace_live_message_iterator_finalize(
	bt_self_message_iterator *self_message_iterator)
{
	struct ftrace_live_iterator *iterator =
		bt_self_message_iterator_get_data(self_message_iterator);

	if (!iterator)
		return;
	ftrace_clear_pending_stack(&iterator->pending_stack);
	trace_seq_destroy(&iterator->seq);
	BT_PACKET_PUT_REF_AND_RESET(iterator->packet);
	tracefs_cpu_close(iterator->cpu);
	free(iterator);
}

bt_message_iterator_class_next_method_status ftrace_live_message_iterator_next(
	bt_self_message_iterator *self_message_iterator,
	bt_message_array_const messages, uint64_t capacity, uint64_t *count)
{
	struct ftrace_live_iterator *iterator =
		bt_self_message_iterator_get_data(self_message_iterator);
	uint64_t message_count = 0;

	while (message_count < capacity) {
		bt_message *message;

		if (iterator->state == FTRACE_LIVE_ITERATOR_STATE_EVENT &&
			!iterator->record_ready) {
			/*
			 * Only keep polling while tracing is explicitly on. A zero
			 * (tracing off) or negative (tracing_on unreadable) result must
			 * end the stream, otherwise the iterator would spin forever
			 * returning AGAIN without any data ever arriving.
			 */
			if (tracefs_trace_is_on(iterator->live->instance) > 0) {
				if (read_live_record(iterator))
					goto emit;
				/* Tracing may have stopped between the check and the read. */
				if (tracefs_trace_is_on(iterator->live->instance) > 0)
					break;
			}
			if (flush_live_record(iterator))
				continue;
			iterator->state = FTRACE_LIVE_ITERATOR_STATE_STREAM_ENDING;
		}
emit:
		message = create_live_message(iterator, self_message_iterator);
		if (message)
			messages[message_count++] = message;
		else if (iterator->state == FTRACE_LIVE_ITERATOR_STATE_ENDED)
			break;
	}
	if (message_count) {
		*count = message_count;
		return BT_MESSAGE_ITERATOR_CLASS_NEXT_METHOD_STATUS_OK;
	}
	if (iterator->state == FTRACE_LIVE_ITERATOR_STATE_ENDED)
		return BT_MESSAGE_ITERATOR_CLASS_NEXT_METHOD_STATUS_END;
	return BT_MESSAGE_ITERATOR_CLASS_NEXT_METHOD_STATUS_AGAIN;
}

bt_component_class_get_supported_mip_versions_method_status
ftrace_live_get_supported_mip_versions(
	bt_self_component_class_source *self_component_class,
	const bt_value *params, void *initialize_method_data,
	bt_logging_level logging_level,
	bt_integer_range_set_unsigned *supported_versions)
{
	if (bt_integer_range_set_unsigned_add_range(supported_versions, 0, 1) !=
		BT_INTEGER_RANGE_SET_ADD_RANGE_STATUS_OK) {
		return BT_COMPONENT_CLASS_GET_SUPPORTED_MIP_VERSIONS_METHOD_STATUS_MEMORY_ERROR;
	}
	return BT_COMPONENT_CLASS_GET_SUPPORTED_MIP_VERSIONS_METHOD_STATUS_OK;
}
