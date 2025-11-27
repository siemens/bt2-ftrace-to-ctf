/**
 * SPDX-FileCopyrightText: (C) 2025 Siemens
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Minimal ftrace (trace.dat) source component for babeltrace
 * 
 * The source component uses the following initialization parameters:
 * 
 * "inputs": array of string, mandatory: providing exactly one input file path
 * "lttng": boolean, optional: indicating if LTTng semantics shall be used
 * "clock-offset": uint64, optional: trace clock offset from world clock in ns
 * "clock-uid": string, optional: UID or UUID of the trace clock
 * "trace-name": string, optional: trace name and `env.trace_name` property
 * "trace-creation-datetime": string (ISO‑8601), optional: `env.trace_creation_datetime` property
 *
 * Example:
 *   trace-cmd record -C mono -e "sched:sched_switch" sleep 1
 *   babeltrace2 --plugin-path=. trace.dat
 * 
 * Query babeltrace.trace-infos:
 *   babeltrace2 --plugin-path=. query -p "inputs=[trace.dat]"
 *     source.ftrace.tracedat babeltrace.trace-infos
 *
 */

#define _GNU_SOURCE

#include "config.h"
#include "bt-ftrace-lttng-events.h"
#include "bt-ftrace-logging.h"
#include "bt-ftrace-source.h"
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

#define NS_PER_S (1000 * 1000 * 1000)

/* ports private data */
struct port_in {
	int cpu_id;
};

/* Source component's private data */
struct ftrace_in {
	/* Logging */
	bt_logging_level log_level;

	/* kernel trace handles */
	struct tracecmd_input *tc_input;
	struct tep_handle *tep;

	/* use LTTng event names and semantics on well-known events */
	bt_bool lttng_format;

	/* tracer and trace metadata */
	char *trace_name;
	char *trace_sysname;
	char *trace_hostname;
	char *trace_kernel_release;
	char *trace_creation_datetime;
	int tracer_version_major;
	int tracer_version_minor;

	/* clock offset to world clock in ns */
	uint64_t clock_offset_ns;
	char *clock_uid;

	/* Streams (owned by this) */
	bt_stream **streams;
	unsigned int nb_streams;

	/* Event classes for each type of event (owned by this) */
	GHashTable *event_classes;

	/* Private data of output ports */
	struct port_in **port_data;
	unsigned int nb_port_data;
};

/*
 * Parse options of the trace.dat file
 */
static void parse_tracedat_opts(struct ftrace_in *ftrace_in)
{
#if WITH_TRACE_CMD_PRIVATE_SYMBOLS
	const char *uname = tracecmd_get_uname(ftrace_in->tc_input);
	char *uname_copy = strdup(uname);
	ftrace_in->trace_sysname = strdup(strtok(uname_copy, " "));
	ftrace_in->trace_hostname = strdup(strtok(NULL, " "));
	ftrace_in->trace_kernel_release = strdup(strtok(NULL, " "));
	free(uname_copy);
#else
	ftrace_in->trace_sysname = strdup("Linux");
#endif
}

/*
 * Creates an event class within `stream_class` from a ftrace event.
 */
static bt_event_class *create_event_class(bt_stream_class *stream_class,
										  struct tep_event *event,
										  const struct ftrace_in *ftrace_in)
{
	char NAME_BUF[128];
	struct tep_format_field **fields = NULL;
	bt_field_class *field_class;
	const bt_logging_level loglvl = ftrace_in->log_level;

	/* Borrow trace class from stream class */
	bt_trace_class *trace_class =
		bt_stream_class_borrow_trace_class(stream_class);

	/* Create a default event class */
	bt_event_class *event_class = bt_event_class_create(stream_class);

	/*
	* Create an empty structure field class to be used as the
	* event class's payload field class.
	*/
	bt_field_class *payload_field_class =
		bt_field_class_structure_create(trace_class);

	/* Name the event class */
	if (ftrace_in->lttng_format) {
		strcpy(NAME_BUF, lttng_get_event_name_from_event(event));
	} else {
		sprintf(NAME_BUF, "%s:%s", event->system, event->name);
	}
	bt_event_class_set_name(event_class, NAME_BUF);
	BT_FTRACE_LOG_INFO(loglvl, "create event %s", NAME_BUF);

	fields = tep_event_fields(event);
	for (int j = 0; fields[j]; j++) {
		const char *field_name;
		BT_FTRACE_LOG_DEBUG(loglvl, "  %s:%s:%d:%d|%d", fields[j]->name,
							fields[j]->type, fields[j]->offset, fields[j]->size,
							fields[j]->arraylen);

		if (ftrace_in->lttng_format) {
			field_name =
				lttng_get_field_name_from_event(event, fields[j]->name);
		} else {
			field_name = fields[j]->name;
		}
		const unsigned long flags = fields[j]->flags;
		if (flags & TEP_FIELD_IS_STRING) {
			field_class = bt_field_class_string_create(trace_class);
		} else if ((flags & TEP_FIELD_IS_POINTER ||
					flags & TEP_FIELD_IS_DYNAMIC ||
					flags & TEP_FIELD_IS_SYMBOLIC ||
					flags & TEP_FIELD_IS_RELATIVE) ||
				   fields[j]->size == 0 || fields[j]->size > 8) {
			BT_FTRACE_LOG_DEBUG(loglvl, "   skip field %s, type: %s",
								field_name, fields[j]->type);
			/* TODO */
			continue;
		} else if (flags & TEP_FIELD_IS_ARRAY) {
			BT_FTRACE_LOG_DEBUG(loglvl, "   skip field %s, type: %s",
								field_name, fields[j]->type);
			/* TODO */
			continue;
		} else if (flags & TEP_FIELD_IS_SIGNED) {
			field_class = bt_field_class_integer_signed_create(trace_class);
			bt_field_class_integer_set_field_value_range(field_class,
														 fields[j]->size * 8);
		} else {
			field_class = bt_field_class_integer_unsigned_create(trace_class);
			bt_field_class_integer_set_field_value_range(field_class,
														 fields[j]->size * 8);
		}
		if (bt_field_class_structure_borrow_member_by_name(payload_field_class,
														   field_name)) {
			BT_FTRACE_LOG_WARNING(loglvl,
								  "   skip duplicated field %s, type: %s on %s",
								  field_name, fields[j]->type, NAME_BUF);
		} else {
			bt_field_class_structure_append_member(payload_field_class,
												   field_name, field_class);
		}
		bt_field_class_put_ref(field_class);
	}
	free(fields);

	/* Set the event class's payload field class */
	bt_event_class_set_payload_field_class(event_class, payload_field_class);

	/* Put the references we don't need anymore */
	bt_field_class_put_ref(payload_field_class);

	return event_class;
}

/*
 * Creates the source component's metadata and stream objects.
 */
static void create_metadata_and_stream(bt_self_component *self_component,
									   struct ftrace_in *ftrace_in)
{
	char NAME_BUF[32];
	const uint64_t mip_version =
		bt_self_component_get_graph_mip_version(self_component);
	/* assume monotonic clock if not provided otherwise */
	const char *traceclock = "mono";
	bt_bool clock_is_monotonic = true;

	/* Create a default trace class */
	bt_trace_class *trace_class = bt_trace_class_create(self_component);

	/* Create a stream trace class within `trace_class` */
	bt_stream_class *stream_class = bt_stream_class_create(trace_class);
	bt_stream_class_set_name(stream_class, "ftrace-stream");

#if WITH_TRACE_CMD_PRIVATE_SYMBOLS
	traceclock = tracecmd_get_trace_clock(ftrace_in->tc_input);
#endif
	/* Create a default clock class (1 GHz frequency) */
	bt_clock_class *clock_class = bt_clock_class_create(self_component);
	if (strcmp(traceclock, "mono") == 0 ||
		strcmp(traceclock, "mono_raw") == 0) {
		bt_clock_class_set_name(clock_class, "monotonic");
		bt_clock_class_set_description(clock_class, "Monotonic Clock");
	} else {
		clock_is_monotonic = false;
		bt_clock_class_set_name(clock_class, traceclock);
	}
	/* make the clock compatible with an LTTng US clock definition */
	if (ftrace_in->clock_offset_ns) {
		bt_clock_class_set_offset(clock_class,
								  ftrace_in->clock_offset_ns / NS_PER_S,
								  ftrace_in->clock_offset_ns % NS_PER_S);
		bt_clock_class_origin_is_unix_epoch(clock_class);
	} else {
#if HAS_BT2_CLOCK_UNKNOWN
		bt_clock_class_set_origin_unknown(clock_class);
#endif
	}
	if (ftrace_in->clock_uid) {
		uuid_t clock_uuid;
		if (mip_version == 0) {
			uuid_parse(ftrace_in->clock_uid, clock_uuid);
			bt_clock_class_set_uuid(clock_class, clock_uuid);
		} else {
#if HAS_BT2_CLOCK_UID
			bt_clock_class_set_uid(clock_class, ftrace_in->clock_uid);
#endif
		}
		if (!clock_is_monotonic) {
			BT_FTRACE_LOG_WARNING(
				ftrace_in->log_level,
				"ftrace used non-monotonic clock \"%s\". Traces are likely misaligned.",
				traceclock);
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
	bt_stream_class_set_default_clock_class(stream_class, clock_class);
	bt_stream_class_set_supports_discarded_events(stream_class, BT_TRUE,
												  BT_TRUE);

#if USE_PACKAGES
	bt_stream_class_set_supports_packets(stream_class, BT_TRUE, BT_TRUE,
										 BT_TRUE);
	bt_stream_class_set_supports_discarded_packets(stream_class, BT_TRUE,
												   BT_TRUE);

	bt_field_class *packet_ctx_class =
		bt_field_class_structure_create(trace_class);
	bt_field_class *field_cpuid_class =
		bt_field_class_integer_unsigned_create(trace_class);
	bt_field_class_structure_append_member(packet_ctx_class, "cpu_id",
										   field_cpuid_class);
	bt_stream_class_set_packet_context_field_class(stream_class,
												   packet_ctx_class);
	bt_field_class_put_ref(field_cpuid_class);
	bt_field_class_put_ref(packet_ctx_class);
#endif

	/* Create the two event classes we need */
	struct tep_event **events = NULL;
	ftrace_in->event_classes =
		g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
							  (GDestroyNotify)bt_event_class_put_ref);
	events = tep_list_events(ftrace_in->tep, TEP_EVENT_SORT_ID);
	for (int i = 0; events[i]; i++) {
		const bt_event_class *event_class =
			create_event_class(stream_class, events[i], ftrace_in);
		g_hash_table_insert(ftrace_in->event_classes,
							(gpointer)((uintptr_t)events[i]->id),
							(gpointer)event_class);
	}

	/* Create a default trace from (instance of `trace_class`) */
	bt_trace *trace = bt_trace_create(trace_class);
	sprintf(NAME_BUF, "%llu", tracecmd_get_traceid(ftrace_in->tc_input));
#if HAS_BT2_HAS_TRACE_UID
	if (mip_version >= 2) {
		bt_trace_set_uid(trace, NAME_BUF);
	}
#endif
	if (ftrace_in->trace_name) {
		bt_trace_set_name(trace, ftrace_in->trace_name);
	}
	bt_trace_set_environment_entry_string(trace, "domain", "kernel");
	bt_trace_set_environment_entry_string(trace, "sysname",
										  ftrace_in->trace_sysname);
	if (ftrace_in->trace_kernel_release) {
		bt_trace_set_environment_entry_string(trace, "kernel_release",
											  ftrace_in->trace_kernel_release);
	}
	bt_trace_set_environment_entry_string(trace, "trace_buffering_scheme",
										  "global");
	if (ftrace_in->trace_name) {
		bt_trace_set_environment_entry_string(trace, "trace_name",
											  ftrace_in->trace_name);
	}
	/* The CTF sink dispatches based on this value. Fake it */
	bt_trace_set_environment_entry_string(
		trace, "tracer_name",
		ftrace_in->lttng_format ? "lttng-modules" : "ftrace");

	bt_trace_set_environment_entry_integer(trace, "tracer_major",
										   ftrace_in->lttng_format ?
											   LTTNG_VERSION_MAJOR :
											   ftrace_in->tracer_version_major);
	bt_trace_set_environment_entry_integer(trace, "tracer_minor",
										   ftrace_in->lttng_format ?
											   LTTNG_VERSION_MINOR :
											   ftrace_in->tracer_version_minor);

	if (ftrace_in->trace_hostname) {
		bt_trace_set_environment_entry_string(trace, "hostname",
											  ftrace_in->trace_hostname);
	}
	if (ftrace_in->trace_creation_datetime) {
		bt_trace_set_environment_entry_string(
			trace, "trace_creation_datetime",
			ftrace_in->trace_creation_datetime);
	}

	/*
	 * Create one stream per CPU stream in ftrace data
	 */
	const int ncpus = tep_get_cpus(ftrace_in->tep);
	ftrace_in->nb_streams = ncpus;
	ftrace_in->streams = calloc(ncpus, sizeof(bt_stream *));
	for (int i = 0; i < ncpus; ++i) {
		sprintf(NAME_BUF, "channel0_%d", i);
		ftrace_in->streams[i] = bt_stream_create(stream_class, trace);
		bt_stream_set_name(ftrace_in->streams[i], NAME_BUF);
	}

	bt_trace_put_ref(trace);
	bt_clock_class_put_ref(clock_class);
	bt_stream_class_put_ref(stream_class);
	bt_trace_class_put_ref(trace_class);
}

/*
 * Initializes the source component.
 */
bt_component_class_initialize_method_status
ftrace_in_initialize(bt_self_component_source *self_component_source,
					 bt_self_component_source_configuration *configuration,
					 const bt_value *params, void *initialize_method_data)
{
	/* Allocate a private data structure */
	char NAME_BUF[16];
	struct ftrace_in *ftrace_in = calloc(1, sizeof(*ftrace_in));
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
	const bt_value *lttng_val =
		bt_value_map_borrow_entry_value_const(params, "lttng");
	if (lttng_val) {
		ftrace_in->lttng_format = bt_value_bool_get(lttng_val);
	}
	const bt_value *clock_of_val =
		bt_value_map_borrow_entry_value_const(params, "clock-offset");
	if (clock_of_val) {
		ftrace_in->clock_offset_ns =
			bt_value_integer_unsigned_get(clock_of_val);
	}
	const bt_value *clock_uid_val =
		bt_value_map_borrow_entry_value_const(params, "clock-uid");
	if (clock_uid_val) {
		ftrace_in->clock_uid = strdup(bt_value_string_get(clock_uid_val));
	}
	const bt_value *trace_name_val =
		bt_value_map_borrow_entry_value_const(params, "trace-name");
	if (trace_name_val) {
		ftrace_in->trace_name = strdup(bt_value_string_get(trace_name_val));
	}
	const bt_value *trace_date_val = bt_value_map_borrow_entry_value_const(
		params, "trace-creation-datetime");
	if (trace_date_val) {
		ftrace_in->trace_creation_datetime =
			strdup(bt_value_string_get(trace_date_val));
	}

	ftrace_in->tc_input = tracecmd_open(path, TRACECMD_FL_LOAD_NO_PLUGINS);
	if (!ftrace_in->tc_input) {
		free(ftrace_in);
		return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_ERROR;
	}
	ftrace_in->tep = tracecmd_get_tep(ftrace_in->tc_input);
	const int ncpus = tep_get_cpus(ftrace_in->tep);
	BT_FTRACE_LOG_INFO(ftrace_in->log_level, "the trace has %d CPUs", ncpus);

	parse_tracedat_opts(ftrace_in);

	bt_self_component *self_component =
		bt_self_component_source_as_self_component(self_component_source);

	/* Create the source component's metadata and stream objects */
	create_metadata_and_stream(self_component, ftrace_in);
	bt_self_component_set_data(self_component, ftrace_in);

	/* Add one output port per CPU stream */
	ftrace_in->port_data = calloc(ncpus, sizeof(struct port_in *));
	ftrace_in->nb_port_data = ncpus;
	for (int i = 0; i < ncpus; ++i) {
		sprintf(NAME_BUF, "out%d", i);
		ftrace_in->port_data[i] = calloc(1, sizeof(struct port_in));
		struct port_in *port_priv = ftrace_in->port_data[i];
		port_priv->cpu_id = i;
		bt_self_component_source_add_output_port(self_component_source,
												 NAME_BUF, port_priv, NULL);
	}

	return BT_COMPONENT_CLASS_INITIALIZE_METHOD_STATUS_OK;

param_error:
	BT_FTRACE_LOG_ERROR(ftrace_in->log_level,
						"ftrace source: missing mandatory parameter inputs");
	free(ftrace_in);
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

	tracecmd_close(ftrace_in->tc_input);

	/* Put all references */
	g_hash_table_unref(ftrace_in->event_classes);
	for (unsigned i = 0; i < ftrace_in->nb_streams; ++i) {
		bt_stream_put_ref(ftrace_in->streams[i]);
	}

	/* Free the allocated structure */
	free(ftrace_in->streams);
	for (unsigned i = 0; i < ftrace_in->nb_port_data; ++i) {
		free(ftrace_in->port_data[i]);
	}
	free(ftrace_in->port_data);
	free(ftrace_in->clock_uid);
	free(ftrace_in->trace_name);
	free(ftrace_in->trace_hostname);
	free(ftrace_in->trace_sysname);
	free(ftrace_in->trace_kernel_release);
	free(ftrace_in->trace_creation_datetime);
	free(ftrace_in);
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

	/* current packet instance */
	bt_packet *packet;
	uint64_t events_in_pkg;
	/* we need to report n discarded events*/
	long long events_discarded;

	/* last processed record */
	struct tep_record *rec;
	unsigned long long last_rec_ts;

	/* ftrace stream id (one per CPU) */
	int cpu_id;

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
	ftrace_in_iter->cpu_id = port_data->cpu_id;
	ftrace_in_iter->rec =
		tracecmd_read_cpu_first(ftrace_in->tc_input, ftrace_in_iter->cpu_id);

	/* Set the message iterator's initial state */
	ftrace_in_iter->state = FTRACE_IN_MESSAGE_ITERATOR_STATE_STREAM_BEGINNING;
	ftrace_in_iter->events_in_pkg = 0;
	ftrace_in_iter->events_discarded = 0;

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

	tracecmd_free_record(ftrace_in_iter->rec);

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
	bt_message *message;
	bt_stream *stream =
		ftrace_in_iter->ftrace_in->streams[ftrace_in_iter->cpu_id];
	struct tep_record *rec = ftrace_in_iter->rec;
	struct tep_event *trace_event;
	struct tep_format_field **fields;
	unsigned long long val;
	const bt_bool lttng = ftrace_in_iter->ftrace_in->lttng_format;

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

	trace_event = tep_find_event_by_record(ftrace_in_iter->ftrace_in->tep, rec);
	if (!trace_event) {
		/* TODO: skip */
		BT_FTRACE_LOG_ERROR(ftrace_in_iter->ftrace_in->log_level,
							"unknown event");
		goto done;
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
	bt_field *data_field = NULL;

	fields = tep_event_fields(trace_event);
	for (int j = 0; fields[j]; j++) {
		const char *field_name;
		if (lttng) {
			field_name =
				lttng_get_field_name_from_event(trace_event, fields[j]->name);
		} else {
			field_name = fields[j]->name;
		}

		data_field = bt_field_structure_borrow_member_field_by_name(
			payload_field, field_name);
		if (!data_field) {
			BT_FTRACE_LOG_DEBUG(ftrace_in_iter->ftrace_in->log_level,
								"skip unknown field \"%s\" on %s:%s",
								field_name, trace_event->system,
								trace_event->name);
			continue;
		}
		const bt_field_class_type data_class =
			bt_field_get_class_type(data_field);
		if (bt_field_class_type_is(BT_FIELD_CLASS_TYPE_STRING, data_class)) {
			int len;
			char *strdata =
				tep_get_field_raw(NULL, trace_event, field_name, rec, &len, 0);
			bt_field_string_set_value(data_field, strdata);
		} else if (bt_field_class_type_is(BT_FIELD_CLASS_TYPE_SIGNED_INTEGER,
										  data_class)) {
			tep_get_field_val(NULL, trace_event, fields[j]->name, rec, &val, 0);
			if (lttng)
				val = lttng_get_field_val_from_event(trace_event, field_name,
													 val);
			bt_field_integer_signed_set_value(data_field, (int64_t)val);
		} else if (bt_field_class_type_is(BT_FIELD_CLASS_TYPE_UNSIGNED_INTEGER,
										  data_class)) {
			tep_get_field_val(NULL, trace_event, fields[j]->name, rec, &val, 0);
			if (lttng)
				val = lttng_get_field_val_from_event(trace_event, field_name,
													 val);
			bt_field_integer_unsigned_set_value(data_field, (uint64_t)val);
		} else {
			/* do nothing */
		}
	}
	free(fields);

	ftrace_in_iter->events_in_pkg++;

	/*
	 * Memorize the last rec timestamp so we can use it in the end package message
	 * and in discarded event messages.
	 */
	ftrace_in_iter->last_rec_ts = rec->ts;

	/* read next record */
	tracecmd_free_record(rec);
	ftrace_in_iter->rec = tracecmd_read_data(
		ftrace_in_iter->ftrace_in->tc_input, ftrace_in_iter->cpu_id);
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
		} else {
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
