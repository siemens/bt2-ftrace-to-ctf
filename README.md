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

The plugin uses the following initialization parameters:

- "inputs": array of string, mandatory: providing exactly one input file path
- "lttng": boolean, optional: indicating if LTTng semantics shall be used
- "clock-offset": uint64, optional: trace clock offset from world clock in ns
- "clock-uid": string, optional: UID or UUID of the trace clock

The plugin further implements the following query interfaces:

- `babeltrace.support-info`
- `babeltrace.trace-infos`

**Example:**

```bash
trace-cmd record -C mono -e "sched:sched_switch" sleep 1
babeltrace2 --plugin-path=. trace.dat
```

## trace.dat to CTF LTTng CTF converter

The converter uses `libbabeltrace2` and the `ftrace` plugin to perform the conversion.
The resulting trace can be opened with tracecompass as LTTng kernel trace.

**Example:**

```bash
export BABELTRACE_PLUGIN_PATH=$(pwd)
./ftrace-to-ctf --lttng trace.dat /tmp/traceout
```

## Licenses

The babeltrace2 plugin is licensed under the LGPL-2.1-or-newer license, the converter is licensed under MIT.
All source and header files provide SPDX headers.

## Maintainers

- Felix Moessbauer <felix.moessbauer@siemens.com>
