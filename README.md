<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: (C) 2025 Siemens
-->
# Kernel ftrace to CTF converter

This repository contains two components:

- a Babeltrace2 plugin to read trace-cmd's trace.dat file
- a program to convert the trace.dat into an LTTng (alike) kernel trace in CTF format

*Note*: The project is still in a very early state. Expect things to break!

## Babeltrace2 Plugin (ftrace)

The plugin provides three components:

- `source.ftrace.tracedat`: read a trace.dat file
- `source.ftrace.live`: read an already configured live kernel ftrace instance
- `sink.ftrace.tracemeta`: emit clock definitions in JSON format for any stream begin message

### Source Parameters

Both source components accept these optional parameters:

- `lttng`: use LTTng semantics for well-known events
- `symbolize`: symbolize function addresses
- `callstack`: add available callstack information to event context
- `clock-offset`: trace clock offset from world clock in ns
- `clock-uid`: UID or UUID of the trace clock
- `clock-namespace`: trace clock namespace (Babeltrace 2.1+)
- `clock-name`: trace clock name (Babeltrace 2.1+)
- `trace-name`: trace name and `env.trace_name` property
- `trace-creation-datetime`: ISO-8601 `env.trace_creation_datetime` property

### Plugin `source.ftrace.tracedat`

The mandatory `inputs` parameter is an array containing exactly one trace.dat file path.

The plugin further implements the following query interfaces:

- `babeltrace.support-info`
- `babeltrace.trace-infos`

**Example:**

```bash
trace-cmd record -C mono -e "sched:sched_switch" sleep 1
babeltrace2 --plugin-path=. trace.dat
```

### Plugin `source.ftrace.live`

**Requires libtracefs 1.8.0**.

The live source consumes an existing tracefs buffer. It never enables events,
starts or stops tracing, clears buffers, or creates and destroys instances.

The mandatory `inputs` parameter is an array containing exactly one tracefs root (for example `/sys/kernel/tracing`) or existing instance directory (for example `/sys/kernel/tracing/instances/my-instance`).

The source creates one output port per CPU. It is non-seekable and continues
until Babeltrace destroys the graph. Packets align with tracefs ring-buffer
sub-buffers. It implements the `babeltrace.support-info` and
`babeltrace.trace-infos` query interfaces. Live stream ranges are reported as
`0` to `INT64_MAX`.

While a CPU buffer holds no data, the source never blocks the processing graph
and reports "try again later" instead. Babeltrace then waits for the duration
of `--retry-duration` (100 ms by default) before it polls the buffers again,
so this value defines the polling interval and the latency of the live output.

**Example:**

```bash
# Configure and start an isolated ftrace instance outside the plugin.
trace-cmd start -B bt-live -e sched:sched_switch

# Consume it without changing its configuration.
babeltrace2 --plugin-path=. /sys/kernel/tracing/instances/bt-live

# Poll the buffers every 10 ms instead of every 100 ms.
babeltrace2 --plugin-path=. --retry-duration=10000 /sys/kernel/tracing/instances/bt-live
```

### Plugin `sink.ftrace.tracemeta`

This plugin allows to gather information about trace clocks of a stream.
The gathered data is written as JSON output either to standard out (default)
or to a user-provided file descriptor. The output format is in json lines,
whereby each object is as following:

```
{
  trace: { (uid: <str> | uuid: <str>)? },
  stream: { id: <int>, name: <str>},
  clock: { 
    offset_s: int,
    offset_c: int,
    frequency: int,
    origin-is-unix-epoch: bool,
    (uid: str | uuid: str)?
  },
  env: { { name: value }, ... }
}
```

The plugin uses the following initialization parameters:

- "outfd": int, optional: file descriptor to write output data to

**Example:**

```bash
babeltrace2 --plugin-path=. --component=meta:sink.ftrace.tracemeta /path/to/lttng-us/trace
```

## trace.dat to CTF LTTng CTF converter

The converter uses `libbabeltrace2` and the `ftrace` plugin to perform the conversion.
The resulting trace can be opened with tracecompass as LTTng kernel trace.

**Example:**

```bash
export BABELTRACE_PLUGIN_PATH=$(pwd)
./ftrace-to-ctf --lttng trace.dat /tmp/traceout
# combine an ftrace with a LTTng US trace
./ftrace-to-ctf --lttng trace.dat /path/to/lttng-us/trace /tmp/traceout
```

## Licenses

The babeltrace2 plugin is licensed under the LGPL-2.1-or-newer license, the converter is licensed under MIT.
All source and header files provide SPDX headers.

## Maintainers

- Felix Moessbauer <felix.moessbauer@siemens.com>
