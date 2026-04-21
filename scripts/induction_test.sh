#!/bin/bash

# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
# SPDX-License-Identifier: MIT

PASS=0
FAIL=0

pass() { echo "  ✅ PASS: $1"; ((PASS++)); }
fail() { echo "  ❌ FAIL: $1"; ((FAIL++)); }

check_field_absent() {
    local label="$1"
    local field="$2"
    local trace="$3"

    if babeltrace2 "$trace" 2>/dev/null | grep -q "\"${field}\""; then
        fail "$label — field '${field}' should NOT be present but was found"
    else
        pass "$label — field '${field}' correctly absent"
    fi
}

check_field_present() {
    local label="$1"
    local field="$2"
    local trace="$3"

    if babeltrace2 "$trace" 2>/dev/null | grep -q "${field}"; then
        pass "$label — field '${field}' correctly present"
    else
        fail "$label — field '${field}' should be present but was NOT found"
    fi
}

check_event_absent() {
    local label="$1"
    local event="$2"
    local trace="$3"

    if babeltrace2 "$trace" 2>/dev/null | grep -q "\"${event}\""; then
        fail "$label — field '${event}' should NOT be present but was found"
    else
        pass "$label — field '${event}' correctly absent"
    fi
}

check_event_present() {
    local label="$1"
    local event="$2"
    local trace="$3"

    if babeltrace2 "$trace" 2>/dev/null | grep -q "${event}"; then
        pass "$label — event '${event}' found in output"
    else
        fail "$label — event '${event}' NOT found in output"
    fi
}

check_output_not_empty() {
    local label="$1"
    local trace="$2"

    local count
    count=$(babeltrace2 "$trace" 2>/dev/null | wc -l)
    if [ "$count" -gt 0 ]; then
        pass "$label — output contains $count lines"
    else
        fail "$label — output is empty!"
    fi
}

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ] || [ -z "$4" ] || [ -z "$5" ]; then
    echo "Usage: $0 <ftrace-to-ctf-binary> <trace.dat> <lttng-ust-dir> <output-dir> <output-dir-dat>"
    exit 1
fi

check_event_no_prefix() {
    local label="$1"
    local prefix="$2"
    local event_suffix="$3"
    local trace="$4"

    local output
    output=$(babeltrace2 "$trace" 2>/dev/null \
        | grep -P "(${event_suffix})" \
        | grep -Pv "(${prefix}_)(${event_suffix})")

    if [[ -n "$output" ]]; then
        fail "$label — event '${event_suffix}' found WITHOUT prefix '${prefix}_'"
    else
        pass "$label — event '${event_suffix}' NOT found without prefix '${prefix}_'"
    fi
}
BINARY="$1"
TRACE_DAT="$2"
LTTNG_UST_DIR="$3"
OUTPUT_DIR="$4"
OUTPUT_DIR_DAT="$5"

echo ""
echo "================================================"
echo " Induction Test — ftrace-to-ctf"
echo "================================================"
echo ""

for path in "$BINARY" "$TRACE_DAT" "$LTTNG_UST_DIR"; do
    if [ ! -e "$path" ]; then
        echo "❌ Error: path not found: $path"
        exit 1
    fi
done


echo "▶ Running ftrace-to-ctf conversion..."
mkdir -p "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR_DAT"

export BABELTRACE_PLUGIN_PATH="$(dirname "$BINARY")"

if "$BINARY" --lttng "$TRACE_DAT" "$OUTPUT_DIR_DAT"; then
    pass "Conversion — ftrace-to-ctf exited successfully"
else
    fail "Conversion — ftrace-to-ctf exited with error"
    echo ""
    echo "⚠️  Conversion failed — skipping validation checks."
    echo "PASS: $PASS | FAIL: $FAIL"
    exit 1
fi

if "$BINARY" --lttng "$TRACE_DAT" "$LTTNG_UST_DIR" "$OUTPUT_DIR"; then
    pass "Conversion — ftrace-to-ctf exited successfully"
else
    fail "Conversion — ftrace-to-ctf exited with error"
    echo ""
    echo "⚠️  Conversion failed — skipping validation checks."
    echo "PASS: $PASS | FAIL: $FAIL"
    exit 1
fi

echo ""
echo "Validating CTF output..."
echo ""

check_output_not_empty "Output not empty" "$OUTPUT_DIR"

check_field_absent "'pid' field absent" "pid" "$OUTPUT_DIR"
check_field_absent "'task' field absent" "task" "$OUTPUT_DIR"
check_field_absent "'common_pid' field absent" "common_pid" "$OUTPUT_DIR"

check_field_present "tid field present"   "tid"  "$OUTPUT_DIR"
check_field_present "procname field present"   "procname"  "$OUTPUT_DIR"
check_field_present "cpu_id field present"   "cpu_id"  "$OUTPUT_DIR"
check_field_present "latency field present"   "latency"  "$OUTPUT_DIR"

check_event_absent "sys_enter event types absent"    "sys_enter"   "$OUTPUT_DIR"

check_event_present "syscall_entry event present"     "syscall_entry"   "$OUTPUT_DIR"

check_event_absent "sys_ prefix events absent"    "sys_"   "$OUTPUT_DIR"

check_event_present "kmem events have 'kmem_' prefix"   "kmem_kmalloc"   "$OUTPUT_DIR"
check_event_present "kmem events have 'kmem_' prefix"   "kmem_kfree"   "$OUTPUT_DIR"
check_event_present "kmem events have 'kmem_' prefix"   "kmem_mm_"   "$OUTPUT_DIR"

check_event_present "timer events have 'timer_' prefix"   "timer_hrtimer"   "$OUTPUT_DIR"
check_event_present "timer events have 'timer_' prefix"   "timer_hrtimer"   "$OUTPUT_DIR"

# Future Work: Check if callstack fields are parsed correctly
#check_field_present "kernelstack field present"   "context._callstack_kernel"  "$OUTPUT_DIR"
#check_field_present "kernelstack length field present" "context.__callstack_kernel_length" "$OUTPUT_DIR"
#check_field_present "userstack field present"   "context._callstack_user"  "$OUTPUT_DIR"
#check_field_present "userstack length field present" "context.__callstack_user_length" "$OUTPUT_DIR"
#check_event_absent "kernelstack events absent"    "kernelstack"   "$OUTPUT_DIR"
#check_event_absent "userstack events absent"     "userstack"     "$OUTPUT_DIR"

echo ""
echo "================================================"
echo " Results: ✅ PASS: $PASS  |  ❌ FAIL: $FAIL"
echo "================================================"
echo ""

if [ "$FAIL" -gt 0 ]; then
    exit 1
else
    exit 0
fi