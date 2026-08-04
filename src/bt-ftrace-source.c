/**
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * ftrace (trace.dat) source component for babeltrace (source.ftrace.tracedat)
 * 
 * The source component uses the following initialization parameters:
 * 
 * "inputs": array of string, mandatory: providing exactly one input file path
 * "lttng": boolean, optional: indicating if LTTng semantics shall be used
 * "symbolize": boolean, optional: symbolize function addresses
 * "clock-offset": uint64, optional: trace clock offset from world clock in ns
 * "clock-uid": string, optional: UID or UUID of the trace clock
 * "clock-namespace": string, optional: namespace of the trace clock (bt 2.1+)
 * "clock-name": string, optional: name of the trace clock (bt 2.1+)
 * "trace-name": string, optional: trace name and `env.trace_name` property
 * "trace-creation-datetime": string (ISO‑8601), optional: `env.trace_creation_datetime` property
 *
 * The source component provides one output port per CPU flight record that
 * has at least one event, according to the following pattern:
 *
 *   Main trace buffer: "out<cpuid>"
 *   Sub buffers: "out-<name><cpuid>"
 *
 * Example:
 *   trace-cmd record -C mono -e "sched:sched_switch" sleep 1
 *   babeltrace2 trace.dat
 * 
 * Query babeltrace.trace-infos:
 *   babeltrace2 query -p "inputs=[trace.dat]"
 *     source.ftrace.tracedat babeltrace.trace-infos
 *
 * Seek in trace:
 *   babeltrace2 --begin=<> --end=<> trace.dat
 */

#define _GNU_SOURCE

#include "config.h"
#include "bt-ftrace-common.h"
#include "bt-ftrace-lttng-events.h"
#include "bt-ftrace-logging.h"
#include "bt-ftrace-source.h"
#include "bt-ftrace-sym-field.h"
#include "bt-ftrace-utils.h"
#if WITH_TRACE_CMD_PRIVATE_SYMBOLS
#include "trace-cmd-private.h"
#endif

#include <babeltrace2/babeltrace.h>
#include <event-parse.h>
#include <glib.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <trace-cmd.h>
#include <uuid.h>

#define USE_PACKAGES 1
/* currently an arbitrary number, but helps to test the next package code path */
#define MAX_EVENTS_PER_PACKET 1024

/* ports private data */
struct port_in {
	int cpu_id;

	/* weak reference */
	struct tracecmd_input *tc_input;

	/* Stream (owned by this) */
	bt_stream *stream;
};

struct tc_buffer {
	struct tracecmd_input *tc_input;
	struct port_in *ports;
	unsigned int nb_ports;
};

/* Source component's private data */
struct ftrace_in {
	/* Logging */
	bt_logging_level log_level;

	/* kernel trace buffer handles */
	struct tc_buffer *tc_buffers;
	unsigned int nb_tc_buffers;
	struct tep_handle *tep;
	/* full path to trace file on disk */
	char *tracedat_path;

	/* Shared source parameters and metadata overrides. */
	struct ftrace_common_options options;

	/* tracer and trace metadata */
	char *trace_sysname;
	char *trace_hostname;
	char *trace_kernel_release;
	int tracer_version_major;
	int tracer_version_minor;

	/* Event classes for each type of event (owned by this) */
	GHashTable *event_classes;

	/* we only have a single stream class (as event classes are per system) */
	bt_stream_class *stream_class;

	bt_trace *trace;
	/* backing storage for trace_identity.uid, which outlives setup */
	char trace_uid[UUID_STR_LEN];
	struct ftrace_trace_identity trace_identity;

	/* mip version of the processing graph */
	uint64_t mip_version;
};

static struct ftrace_common_config
get_common_config(const struct ftrace_in *ftrace_in)
{
	return (struct ftrace_common_config){
		.lttng_format = ftrace_in->options.config.lttng_format,
		.symbolize_funcs = ftrace_in->options.config.symbolize_funcs,
		.with_callstacks = ftrace_in->options.config.with_callstacks,
		.log_level = ftrace_in->log_level,
		.mip_version = ftrace_in->mip_version,
	};
}

/*
 * Parse options of the trace.dat file
 */
static void parse_tracedat_opts(struct ftrace_in *ftrace_in)
{
#if WITH_TRACE_CMD_PRIVATE_SYMBOLS
	const char *uname = tracecmd_get_uname(ftrace_in->tc_buffers[0].tc_input);
	char *uname_copy = strdup(uname);
	char *saveptr = NULL;
	char *tok;

	tok = strtok_r(uname_copy, " ", &saveptr);
	ftrace_in->trace_sysname = tok ? strdup(tok) : strdup("Linux");
	tok = tok ? strtok_r(NULL, " ", &saveptr) : NULL;
	ftrace_in->trace_hostname = tok ? strdup(tok) : NULL;
	tok = tok ? strtok_r(NULL, " ", &saveptr) : NULL;
	ftrace_in->trace_kernel_release = tok ? strdup(tok) : NULL;
	free(uname_copy);
#else
	ftrace_in->trace_sysname = strdup("Linux");
#endif
}

/*
 * Creates the source component's metadata and stream objects.
 */
static void create_metadata_and_trace(bt_self_component *self_component,
									  struct ftrace_in *ftrace_in)
{
	char NAME_BUF[32];
	const uint64_t mip_version =
		bt_self_component_get_graph_mip_version(self_component);
	ftrace_in->mip_version = mip_version;

	/* Create a default trace class */
	bt_trace_class *trace_class = bt_trace_class_create(self_component);

	struct tracecmd_input *tc_main = ftrace_in->tc_buffers[0].tc_input;

#if WITH_TRACE_CMD_PRIVATE_SYMBOLS
	const char *traceclock = tracecmd_get_trace_clock(tc_main);
#else
	/* assume monotonic clock if not provided otherwise */
	const char *traceclock = "mono";
#endif
	/* Create a default clock class (1 GHz frequency) */
	bt_clock_class *clock_class = bt_clock_class_create(self_component);
	ftrace_configure_clock(clock_class, traceclock,
						   ftrace_in->options.clock_name,
						   ftrace_in->options.clock_offset_ns,
						   ftrace_in->options.clock_uid,
						   ftrace_in->options.clock_namespace, mip_version);
	if (ftrace_in->options.clock_uid) {
		if (strcmp(traceclock, "mono") != 0 &&
			strcmp(traceclock, "mono_raw") != 0) {
			BT_FTRACE_LOG_WARNING(
				ftrace_in->log_level,
				"ftrace used non-monotonic clock \"%s\". Traces are likely misaligned.",
				traceclock);
		}
	} else {
		static const uuid_t clock_namespace = FTRACE_CLOCK_UUID_NAMESPACE;
		uuid_t clock_uuid;
		char clock_uid[UUID_STR_LEN];
		char seed[64];

		/*
		 * Derive the clock UID from the clock name. When the clock origin
		 * is unknown (no offset to the world clock is known), a monotonic
		 * clock starts from an arbitrary, per-boot point, so its raw
		 * timestamps are only comparable within the same trace. Mix the
		 * per-trace trace id into the seed in that case, so clocks from
		 * unrelated traces do not share a UID (which babeltrace would treat
		 * as correlatable). All CPU streams of the same trace still share
		 * one clock. When the origin is the Unix epoch, correlation goes
		 * through the epoch, so the name-only UID is kept.
		 */
		const size_t name_len = strlen(traceclock);
		size_t seed_len = name_len < sizeof(seed) ? name_len : sizeof(seed);
		memcpy(seed, traceclock, seed_len);
		if (!ftrace_in->options.clock_offset_ns &&
			seed_len + sizeof(unsigned long long) <= sizeof(seed)) {
			const unsigned long long traceid = tracecmd_get_traceid(tc_main);
			memcpy(seed + seed_len, &traceid, sizeof(traceid));
			seed_len += sizeof(traceid);
		}
		uuid_generate_md5(clock_uuid, clock_namespace, seed, seed_len);
		if (mip_version == 0) {
			bt_clock_class_set_uuid(clock_class, clock_uuid);
		} else {
#if HAS_BT2_CLOCK_UID
			uuid_unparse(clock_uuid, clock_uid);
			bt_clock_class_set_uid(clock_class, clock_uid);
#endif
#if HAS_BT2_CLOCK_NAMESPACE
			/*
			 * Stamp the project namespace so the (namespace, name, uid)
			 * identity is complete. The name was set above from the
			 * trace clock name.
			 */
			bt_clock_class_set_namespace(clock_class, FTRACE_NAMESPACE);
#endif
		}
	}

	/*
	 * Set `clock_class` as the default clock class of `stream_class`.
	 *
	 * This means all the streams created from `stream_class` have a
	 * conceptual default clock which is an instance of `clock_class`.
	 * Any event message created for such a stream has a snapshot of the
	 * stream's default clock.
	 */
	bt_stream_class *stream_class =
		ftrace_create_stream_class(trace_class, clock_class, USE_PACKAGES);

	struct tep_handle *tep =
		tracecmd_get_tep(ftrace_in->tc_buffers[0].tc_input);
	const struct ftrace_common_config config = get_common_config(ftrace_in);
	ftrace_in->event_classes =
		ftrace_create_event_classes(tep, stream_class, &config);

	/* Create a default trace from (instance of `trace_class`) */
	bt_trace *trace = bt_trace_create(trace_class);

	/* Derive a unique, stable trace UID from the trace-cmd trace id */
	const unsigned long long traceid = tracecmd_get_traceid(tc_main);
	uuid_t trace_uuid;
	char *trace_uid = ftrace_in->trace_uid;
	ftrace_derive_trace_uid(traceid, trace_uid);
	uuid_parse(trace_uid, trace_uuid);
	if (mip_version == 0) {
		bt_trace_set_uuid(trace, trace_uuid);
	} else {
#if HAS_BT2_TRACE_UID
		bt_trace_set_uid(trace, trace_uid);
#endif
#if HAS_BT2_TRACE_NAMESPACE
		bt_trace_set_namespace(trace, FTRACE_NAMESPACE);
#endif
	}
	ftrace_in->trace_identity = (struct ftrace_trace_identity){
		.namespace = FTRACE_NAMESPACE,
		.name = ftrace_in->options.trace_name ? ftrace_in->options.trace_name :
												"",
		.uid = trace_uid,
	};
	if (!ftrace_in->options.config.lttng_format) {
		snprintf(NAME_BUF, sizeof(NAME_BUF), "0x%llx", traceid);
		bt_trace_set_environment_entry_string(trace, "tracecmd_traceid",
											  NAME_BUF);
	}

	ftrace_set_trace_environment(trace, &config, ftrace_in->trace_sysname,
								 ftrace_in->trace_kernel_release,
								 ftrace_in->trace_hostname,
								 ftrace_in->options.trace_name,
								 ftrace_in->options.trace_creation_datetime,
								 ftrace_in->tracer_version_major,
								 ftrace_in->tracer_version_minor);

	ftrace_in->trace = trace;
	ftrace_in->stream_class = stream_class;

	bt_clock_class_put_ref(clock_class);
	bt_trace_class_put_ref(trace_class);
}

static int
setup_ports_for_trace_buffer(struct ftrace_in *ftrace_in,
							 bt_self_component_source *self_component_source,
							 struct tc_buffer *tc_buffer,
							 const char *buffer_name, int buffer_index)
{
	struct tep_handle *tep = tracecmd_get_tep(tc_buffer->tc_input);
	const int ncpus = tep_get_cpus(tep);
	BT_FTRACE_LOG_INFO(ftrace_in->log_level,
					   "the trace of buffer \"%s\"has %d CPUs", buffer_name,
					   ncpus);

	/* Add one output port per CPU stream */
	tc_buffer->ports = calloc(ncpus, sizeof(struct port_in));
	tc_buffer->nb_ports = ncpus;
	for (int i = 0; i < ncpus; ++i) {
		struct port_in *pd = &tc_buffer->ports[i];
		pd->cpu_id = i;
		pd->tc_input = tc_buffer->tc_input;

		/* if this stream is empty, do not create a port */
		struct tep_record *rec =
			tracecmd_read_cpu_first(tc_buffer->tc_input, i);
		if (!rec)
			continue;
		tracecmd_free_record(rec);

		const uint64_t stream_id = ((uint64_t)buffer_index << 32) | pd->cpu_id;
		pd->stream = bt_stream_create_with_id(ftrace_in->stream_class,
											  ftrace_in->trace, stream_id);
		char *stream_name = ftrace_format_port_name(
			&ftrace_in->trace_identity, 0, stream_id, ftrace_in->tracedat_path);
		bt_stream_set_name(pd->stream, stream_name);
		bt_self_component_source_add_output_port(self_component_source,
												 stream_name, pd, NULL);
		g_free(stream_name);
	}

	return 0;
}

/*
 * Free all owned strings in ftrace_in and the struct itself.
 */
static void ftrace_in_free(struct ftrace_in *ftrace_in)
{
	free(ftrace_in->tc_buffers);
	free(ftrace_in->tracedat_path);
	free(ftrace_in->options.clock_uid);
	free(ftrace_in->options.clock_namespace);
	free(ftrace_in->options.clock_name);
	free(ftrace_in->options.trace_name);
	free(ftrace_in->trace_hostname);
	free(ftrace_in->trace_sysname);
	free(ftrace_in->trace_kernel_release);
	free(ftrace_in->options.trace_creation_datetime);
	free(ftrace_in);
}

/*
 * Initializes the source component.
 */
bt_component_class_initialize_method_status
ftrace_in_initialize(bt_self_component_source *self_component_source,
					 bt_self_component_source_configuration *configuration,
					 const bt_value *params, void *initialize_method_data)
{
	bt_self_component *self_component =
		bt_self_component_source_as_self_component(self_component_source);

	/* Allocate a private data structure */
	struct ftrace_in *ftrace_in = calloc(1, sizeof(*ftrace_in));
	bt_self_component_set_data(self_component, ftrace_in);

	ftrace_in->tracer_version_major = FT_VERSION_MAJOR;
	ftrace_in->tracer_version_minor = FT_VERSION_MINOR;
	ftrace_in->log_level =
		bt_component_get_logging_level(bt_component_source_as_component_const(
			bt_self_component_source_as_component_source(
				self_component_source)));

	/*Acquire the path information via the babeltrace interface */
	if (!params)
		goto param_error;
	const bt_value *inputs =
		bt_value_map_borrow_entry_value_const(params, "inputs");
	if (!inputs)
		goto param_error;
	if (!bt_value_is_array(inputs) || !bt_value_array_get_length(inputs))
		goto param_error;
	const bt_value *path_value =
		bt_value_array_borrow_element_by_index_const(inputs, 0);
	const char *path = bt_value_string_get(path_value);
	ftrace_in->tracedat_path = strdup(path);
	ftrace_in->options.config.log_level = ftrace_in->log_level;
	ftrace_parse_common_params(params, &ftrace_in->options);

	struct tracecmd_input *tc_main =
		tracecmd_open(path, TRACECMD_FL_LOAD_NO_PLUGINS);
	if (!tc_main) {
		ftrace_in_free(ftrace_in);
		return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
	}
	const int nbuffers = tracecmd_buffer_instances(tc_main);

	ftrace_in->tc_buffers = calloc(nbuffers + 1, sizeof(struct tc_buffer));
	/* first buffer is main buffer */
	ftrace_in->tc_buffers[0].tc_input = tc_main;

	parse_tracedat_opts(ftrace_in);

	/* Create the source component's metadata and even + stream classes */
	create_metadata_and_trace(self_component, ftrace_in);

	/* main buffer */
	setup_ports_for_trace_buffer(ftrace_in, self_component_source,
								 ftrace_in->tc_buffers, NULL, 0);

	/* sub buffers */
	int ret = 0;
	for (int i = 0; i < nbuffers && !ret; ++i) {
		struct tc_buffer *subbuf = &ftrace_in->tc_buffers[i + 1];
		subbuf->tc_input = tracecmd_buffer_instance_handle(tc_main, i);
		const char *buffer_name = tracecmd_buffer_instance_name(tc_main, i);
		ret = setup_ports_for_trace_buffer(ftrace_in, self_component_source,
										   subbuf, buffer_name, i + 1);
	}
	ftrace_in->nb_tc_buffers = nbuffers + 1;

	if (ret) {
		/* TODO: cleanup */
		return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
	}

	return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_OK;

param_error:
	BT_FTRACE_LOG_ERROR(ftrace_in->log_level,
						"ftrace source: missing mandatory parameter inputs");
	ftrace_in_free(ftrace_in);
	return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
}

/*
 * Finalizes the source component.
 */
void ftrace_in_finalize(bt_self_component_source *self_component_source)
{
	/* Retrieve our private data from the component's user data */
	struct ftrace_in *ftrace_in = bt_self_component_get_data(
		bt_self_component_source_as_self_component(self_component_source));

	/* Put all references */
	g_hash_table_unref(ftrace_in->event_classes);
	BT_STREAM_CLASS_PUT_REF_AND_RESET(ftrace_in->stream_class);
	BT_TRACE_PUT_REF_AND_RESET(ftrace_in->trace);

	/* Free the per buffer data */
	for (unsigned i = 0; i < ftrace_in->nb_tc_buffers; ++i) {
		struct tc_buffer *buffer = &ftrace_in->tc_buffers[i];
		for (unsigned j = 0; j < buffer->nb_ports; ++j) {
			BT_STREAM_PUT_REF_AND_RESET(buffer->ports[j].stream);
		}
		free(buffer->ports);
		tracecmd_close(buffer->tc_input);
	}
	ftrace_in_free(ftrace_in);
}

/* State of a message iterator */
enum ftrace_in_message_iterator_state {
	/* Emit a stream beginning message */
	FTRACE_IN_MESSAGE_ITERATOR_STATE_STREAM_BEGINNING,

	/* Emit an event message */
	FTRACE_IN_MESSAGE_ITERATOR_STATE_EVENT,

	/* Message iterator is ended */
	FTRACE_IN_MESSAGE_ITERATOR_STATE_ENDED,
};

/* Message iterator's private data */
struct ftrace_in_message_iterator {
	/* (Weak) link to the component's private data */
	struct ftrace_in *ftrace_in;
	struct port_in *port_data;

	/* current packet instance */
	bt_packet *packet;
	uint64_t events_in_pkg;
	/* we need to report n discarded events*/
	long long events_discarded;

	/* last processed record */
	struct tep_record *rec;
	unsigned long long last_rec_ts;

	/* saved stack */
	struct ftrace_pending_stack pending_stack;

	/* trace sequence buffer */
	struct trace_seq seq;

	/* Current message iterator's state */
	enum ftrace_in_message_iterator_state state;
};

/*
 * Initializes the message iterator.
 */
bt_message_iterator_class_initialize_method_status
ftrace_in_message_iterator_initialize(
	bt_self_message_iterator *self_message_iterator,
	bt_self_message_iterator_configuration *configuration,
	bt_self_component_port_output *self_port)
{
	/* Allocate a private data structure */
	struct ftrace_in_message_iterator *ftrace_in_iter =
		calloc(1, sizeof(*ftrace_in_iter));

	/* Retrieve the component's private data from its user data */
	struct ftrace_in *ftrace_in = bt_self_component_get_data(
		bt_self_message_iterator_borrow_component(self_message_iterator));

	struct port_in *port_data = bt_self_component_port_get_data(
		bt_self_component_port_output_as_self_component_port(self_port));

	/* Keep a link to the component's private data */
	ftrace_in_iter->ftrace_in = ftrace_in;
	ftrace_in_iter->port_data = port_data;
	ftrace_in_iter->rec =
		tracecmd_read_cpu_first(port_data->tc_input, port_data->cpu_id);
	trace_seq_init(&ftrace_in_iter->seq);

	/* Set the message iterator's initial state */
	ftrace_in_iter->state = FTRACE_IN_MESSAGE_ITERATOR_STATE_STREAM_BEGINNING;
	ftrace_in_iter->events_in_pkg = 0;
	ftrace_in_iter->events_discarded = 0;

	/* the iterator supports seeking */
	bt_self_message_iterator_configuration_set_can_seek_forward(configuration,
																BT_TRUE);

	/* Set the message iterator's user data to our private data structure */
	bt_self_message_iterator_set_data(self_message_iterator, ftrace_in_iter);

	return BT_MESSAGE_ITERATOR_CLASS_INITIALIZE_METHOD_STATUS_OK;
}

/*
 * Finalizes the message iterator.
 */
void ftrace_in_message_iterator_finalize(
	bt_self_message_iterator *self_message_iterator)
{
	/* Retrieve our private data from the message iterator's user data */
	struct ftrace_in_message_iterator *ftrace_in_iter =
		bt_self_message_iterator_get_data(self_message_iterator);

	ftrace_clear_pending_stack(&ftrace_in_iter->pending_stack);
	tracecmd_free_record(ftrace_in_iter->rec);
	trace_seq_destroy(&ftrace_in_iter->seq);

	/* Redundant, as the packet is always closed when finishing the stream */
	BT_PACKET_PUT_REF_AND_RESET(ftrace_in_iter->packet);

	/* Free the allocated structure */
	free(ftrace_in_iter);
}

/*
 * Process a single event, load the next trace record and update the internal
 * state machine.
 */
static bt_message *
create_message_from_event(struct ftrace_in_message_iterator *ftrace_in_iter,
						  bt_self_message_iterator *self_message_iterator)
{
	bt_message *message = NULL;
	bt_stream *stream = ftrace_in_iter->port_data->stream;
	struct tep_record *rec = ftrace_in_iter->rec;
	struct tep_event *trace_event;
	struct tep_format_field **fields;

	const bt_bool supports_packets =
		bt_stream_class_supports_packets(bt_stream_borrow_class_const(stream));
	const bt_bool supports_discarded_events =
		bt_stream_class_supports_discarded_events(
			bt_stream_borrow_class_const(stream));

	if (ftrace_in_iter->state ==
		FTRACE_IN_MESSAGE_ITERATOR_STATE_STREAM_BEGINNING) {
		message =
			bt_message_stream_beginning_create(self_message_iterator, stream);
		ftrace_in_iter->state = FTRACE_IN_MESSAGE_ITERATOR_STATE_EVENT;
		return message;
	}

	if (ftrace_in_iter->state == FTRACE_IN_MESSAGE_ITERATOR_STATE_ENDED) {
		return NULL;
	}

	/* close packet */
	if (supports_packets && ftrace_in_iter->packet &&
		(!rec || ftrace_in_iter->events_discarded ||
		 ftrace_in_iter->events_in_pkg > MAX_EVENTS_PER_PACKET)) {
		message = bt_message_packet_end_create_with_default_clock_snapshot(
			self_message_iterator, ftrace_in_iter->packet,
			ftrace_in_iter->last_rec_ts);
		BT_PACKET_PUT_REF_AND_RESET(ftrace_in_iter->packet);
		return message;
	}

	if (!rec) {
		goto done;
	}

	/* discarded events packages may only be emitted between packets */
	if (ftrace_in_iter->events_discarded) {
		message =
			bt_message_discarded_events_create_with_default_clock_snapshots(
				self_message_iterator, stream, ftrace_in_iter->last_rec_ts,
				rec->ts);
		if (ftrace_in_iter->events_discarded != -1) {
			bt_message_discarded_events_set_count(
				message, ftrace_in_iter->events_discarded);
		}
		ftrace_in_iter->events_discarded = 0;
		ftrace_in_iter->events_in_pkg++;
		return message;
	}

	/* if we are not in a packet, start one */
	if (supports_packets && !ftrace_in_iter->packet) {
		bt_packet *packet = bt_packet_create(stream);
		bt_field *context = bt_packet_borrow_context_field(packet);
		bt_field *cpu_id_f =
			bt_field_structure_borrow_member_field_by_name(context, "cpu_id");
		bt_field_integer_unsigned_set_value(cpu_id_f, (unsigned)rec->cpu);

		ftrace_in_iter->packet = packet;
		ftrace_in_iter->events_in_pkg = 0;
		message =
			bt_message_packet_beginning_create_with_default_clock_snapshot(
				self_message_iterator, packet, rec->ts);
		return message;
	}

	struct tep_handle *tep =
		tracecmd_get_tep(ftrace_in_iter->port_data->tc_input);
	trace_event = tep_find_event_by_record(tep, rec);
	if (!trace_event) {
		/* TODO: skip */
		BT_FTRACE_LOG_ERROR(ftrace_in_iter->ftrace_in->log_level,
							"unknown event");
		goto done;
	}

	if (strcmp(trace_event->name, "kernel_stack") == 0) {
		ftrace_read_stack_field(tep, trace_event, rec,
								&ftrace_in_iter->pending_stack.kernel_stack,
								&ftrace_in_iter->pending_stack.klen);
		goto next_record;
	}

	if (strcmp(trace_event->name, "user_stack") == 0) {
		ftrace_read_stack_field(tep, trace_event, rec,
								&ftrace_in_iter->pending_stack.user_stack,
								&ftrace_in_iter->pending_stack.ulen);
		goto next_record;
	}

	struct bt_event_class *event_class =
		g_hash_table_lookup(ftrace_in_iter->ftrace_in->event_classes,
							(gconstpointer)((uintptr_t)trace_event->id));

	if (supports_packets) {
		message =
			bt_message_event_create_with_packet_and_default_clock_snapshot(
				self_message_iterator, event_class, ftrace_in_iter->packet,
				rec->ts);
	} else {
		message = bt_message_event_create_with_default_clock_snapshot(
			self_message_iterator, event_class, stream, rec->ts);
	}
	bt_event *event = bt_message_event_borrow_event(message);
	bt_field *payload_field = bt_event_borrow_payload_field(event);
	bt_field *context_field = bt_event_borrow_specific_context_field(event);

	/* common fields (event context) */
	const struct ftrace_common_config config =
		get_common_config(ftrace_in_iter->ftrace_in);
	ftrace_set_message_common_fields(&config, &ftrace_in_iter->pending_stack,
									 &ftrace_in_iter->seq, trace_event, rec,
									 context_field);

	/* specific fields */
	fields = tep_event_fields(trace_event);
	for (int j = 0; fields[j]; j++) {
		ftrace_set_message_field(&config, &ftrace_in_iter->seq, trace_event,
								 rec, fields[j], payload_field);
	}
	free(fields);

	ftrace_in_iter->events_in_pkg++;

next_record:
	/*
	 * Memorize the last rec timestamp so we can use it in the end package message
	 * and in discarded event messages.
	 */
	ftrace_in_iter->last_rec_ts = rec->ts;

	/* read next record */
	tracecmd_free_record(rec);
	ftrace_in_iter->rec = tracecmd_read_data(
		ftrace_in_iter->port_data->tc_input, ftrace_in_iter->port_data->cpu_id);
	if (supports_discarded_events && ftrace_in_iter->rec) {
		ftrace_in_iter->events_discarded = ftrace_in_iter->rec->missed_events;
	}
	return message;

done:
	message = bt_message_stream_end_create(self_message_iterator, stream);
	ftrace_in_iter->state = FTRACE_IN_MESSAGE_ITERATOR_STATE_ENDED;
	return message;
}

/*
 * Returns the next message to the message iterator's user.
 */
bt_message_iterator_class_next_method_status
ftrace_in_message_iterator_next(bt_self_message_iterator *self_message_iterator,
								bt_message_array_const messages,
								uint64_t capacity, uint64_t *count)
{
	/* Retrieve our private data from the message iterator's user data */
	struct ftrace_in_message_iterator *ftrace_in_iter =
		bt_self_message_iterator_get_data(self_message_iterator);
	bt_message_iterator_class_next_method_status status =
		BT_MESSAGE_ITERATOR_CLASS_NEXT_METHOD_STATUS_OK;

	uint64_t i = 0;

	do {
		bt_message *message =
			create_message_from_event(ftrace_in_iter, self_message_iterator);
		if (message) {
			messages[i++] = message;
		} else if (ftrace_in_iter->state ==
				   FTRACE_IN_MESSAGE_ITERATOR_STATE_ENDED) {
			status = BT_MESSAGE_ITERATOR_CLASS_NEXT_METHOD_STATUS_END;
			break;
		}
	} while (i < capacity);

	if (i > 0) {
		/* if we have any messages pending (including end messages), we need to send
		 * them out first before ending the stream.*/
		*count = i;
		status = BT_MESSAGE_ITERATOR_CLASS_NEXT_METHOD_STATUS_OK;
	}
	return status;
}

bt_message_iterator_class_seek_beginning_method_status
ftrace_in_message_iterator_seek_beginning(
	bt_self_message_iterator *self_message_iterator)
{
	struct ftrace_in_message_iterator *ftrace_in_iter =
		bt_self_message_iterator_get_data(self_message_iterator);

	/* cleanup current state */
	ftrace_clear_pending_stack(&ftrace_in_iter->pending_stack);
	tracecmd_free_record(ftrace_in_iter->rec);
	BT_PACKET_PUT_REF_AND_RESET(ftrace_in_iter->packet);

	/* Set the message iterator's initial state */
	ftrace_in_iter->rec = tracecmd_read_cpu_first(
		ftrace_in_iter->port_data->tc_input, ftrace_in_iter->port_data->cpu_id);

	ftrace_in_iter->events_in_pkg = 0;
	ftrace_in_iter->events_discarded = 0;
	ftrace_in_iter->last_rec_ts = 0;
	ftrace_in_iter->state = FTRACE_IN_MESSAGE_ITERATOR_STATE_STREAM_BEGINNING;

	return BT_MESSAGE_ITERATOR_CLASS_SEEK_BEGINNING_METHOD_STATUS_OK;
}

bt_message_iterator_class_can_seek_beginning_method_status
ftrace_in_message_iterator_can_seek_beginning(
	bt_self_message_iterator *self_message_iterator, bt_bool *can_seek)
{
	*can_seek = BT_TRUE;
	return BT_MESSAGE_ITERATOR_CLASS_CAN_SEEK_BEGINNING_METHOD_STATUS_OK;
}

bt_message_iterator_class_seek_ns_from_origin_method_status
ftrace_in_message_iterator_seek_ns_from_origin(
	bt_self_message_iterator *self_message_iterator, int64_t ns_from_origin)
{
	struct ftrace_in_message_iterator *ftrace_in_iter =
		bt_self_message_iterator_get_data(self_message_iterator);

	const bt_stream *stream = ftrace_in_iter->port_data->stream;
	const bt_bool supports_discarded_events =
		bt_stream_class_supports_discarded_events(
			bt_stream_borrow_class_const(stream));

	/* the cast is safe, as we only allow positive seeking anyways */
	const uint64_t ns_from_orig_pos = (uint64_t)ns_from_origin;
	if (ftrace_in_iter->last_rec_ts < ns_from_orig_pos) {
		while (ftrace_in_iter->rec &&
			   ftrace_in_iter->last_rec_ts < ns_from_orig_pos) {
			ftrace_clear_pending_stack(&ftrace_in_iter->pending_stack);
			tracecmd_free_record(ftrace_in_iter->rec);

			ftrace_in_iter->rec =
				tracecmd_read_data(ftrace_in_iter->port_data->tc_input,
								   ftrace_in_iter->port_data->cpu_id);
			if (supports_discarded_events && ftrace_in_iter->rec) {
				ftrace_in_iter->events_discarded =
					ftrace_in_iter->rec->missed_events;
			}
		}
	} else {
		return BT_MESSAGE_ITERATOR_CLASS_SEEK_NS_FROM_ORIGIN_METHOD_STATUS_ERROR;
	}

	return BT_MESSAGE_ITERATOR_CLASS_SEEK_NS_FROM_ORIGIN_METHOD_STATUS_OK;
}

bt_message_iterator_class_can_seek_ns_from_origin_method_status
ftrace_in_message_iterator_can_seek_ns_from_origin(
	bt_self_message_iterator *self_message_iterator, int64_t ns_from_origin,
	bt_bool *can_seek)
{
	struct ftrace_in_message_iterator *ftrace_in_iter =
		bt_self_message_iterator_get_data(self_message_iterator);
	/* we can only seek forward */
	if (ns_from_origin < 0 ||
		ftrace_in_iter->last_rec_ts > (uint64_t)ns_from_origin) {
		BT_FTRACE_LOG_DEBUG(ftrace_in_iter->ftrace_in->log_level,
							"cannot seek backwards");
		*can_seek = BT_FALSE;
	} else {
		*can_seek = BT_TRUE;
	}
	return BT_MESSAGE_ITERATOR_CLASS_CAN_SEEK_NS_FROM_ORIGIN_METHOD_STATUS_OK;
}

bt_component_class_get_supported_mip_versions_method_status
ftrace_get_supported_mip_versions(
	bt_self_component_class_source *const self_component_class,
	const bt_value *const params, void *const initialize_method_data,
	const bt_logging_level logging_level,
	bt_integer_range_set_unsigned *const supported_versions)
{
	if (bt_integer_range_set_unsigned_add_range(supported_versions, 0, 1) !=
		BT_INTEGER_RANGE_SET_ADD_RANGE_STATUS_OK) {
		return BT_COMPONENT_CLASS_GET_SUPPORTED_MIP_VERSIONS_METHOD_STATUS_MEMORY_ERROR;
	}

	return BT_COMPONENT_CLASS_GET_SUPPORTED_MIP_VERSIONS_METHOD_STATUS_OK;
}
