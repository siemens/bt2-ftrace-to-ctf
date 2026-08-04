# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: MIT
import pytest
import bt2

#Fixtures

@pytest.fixture
def trace_path(pytestconfig):
    return pytestconfig.getoption("--trace-path")

@pytest.fixture
def all_messages(trace_path):
    return list(bt2.TraceCollectionMessageIterator(trace_path))

@pytest.fixture
def event_messages(all_messages):
    return [m for m in all_messages if isinstance(m, bt2._EventMessageConst)]

#Structural sanity

class TestTraceStructure:
    def test_output_not_empty(self, all_messages):
        assert len(all_messages) > 0, "Trace output is empty!"

    def test_stream_and_trace_objects_valid(self, all_messages):
        for msg in all_messages:
            if isinstance(msg, bt2._StreamBeginningMessageConst):
                assert msg.stream is not None
                assert msg.stream.trace is not None
                assert msg.stream.trace.cls is not None
            elif isinstance(msg, bt2._PacketBeginningMessageConst):
                assert msg.packet is not None
                assert msg.packet.stream is not None

#Field absence checks

FORBIDDEN_FIELDS = {"pid", "task", "common_pid"}

class TestForbiddenFields:
    @pytest.mark.parametrize("forbidden_field", sorted(FORBIDDEN_FIELDS))
    def test_forbidden_field_absent(self, event_messages, forbidden_field):
        violations = [
            msg.event.name
            for msg in event_messages
            if forbidden_field in msg.event.payload_field
        ]
        assert violations == [], (
            f"Field '{forbidden_field}' found in events: {violations}"
        )

#Field presence checks

class TestRequiredFields:
    @pytest.mark.parametrize("required_field", ["tid", "procname","latency"])
    def test_required_payload_field_present(self, event_messages, required_field):
        found = False
        for msg in event_messages:
            if msg.event.payload_field is not None and required_field in msg.event.payload_field:
                found = True
                break
            if msg.event.common_context_field is not None and required_field in msg.event.common_context_field:
                found = True
                break
            if msg.event.specific_context_field is not None and required_field in msg.event.specific_context_field:
                found = True
                break  
        assert found, f"Required field '{required_field}' not found in any event payload or context"

    def test_cpu_id_present(self, all_messages):
        for msg in all_messages:
            if isinstance(msg, bt2._PacketBeginningMessageConst):
                if "cpu_id" in msg.packet.context_field:
                    return
        pytest.fail("'cpu_id' not found in any packet context")

#Event name checks

class TestEventNames:
    def test_no_sys_prefix_events(self, event_messages):
        forbidden_sys = [
            msg.event.name for msg in event_messages
            if msg.event.name.startswith("sys_")
        ]
        assert forbidden_sys == [], f"Unexpected sys_ events found: {forbidden_sys}"

    def test_syscall_entry_events_present(self, event_messages):
        found = any(
            msg.event.name.startswith("syscall_entry")
            for msg in event_messages
        )
        assert found, "No syscall_entry events found"

    @pytest.mark.parametrize("expected_event", [
        "kmem_kmalloc",
        "kmem_kfree",
        "kmem_mm_",
        "timer_hrtimer",
        "timer_itimer",
    ])
    def test_expected_prefixed_events_present(self, event_messages, expected_event):
        found = any(
            expected_event in msg.event.name
            for msg in event_messages
        )
        assert found, f"Expected event containing '{expected_event}' not found"

    def test_all_kmem_events_have_prefix(self, event_messages):
        bare_kmem_names = {"kmalloc", "kfree", "mm_page_alloc"}
        bad = [
            msg.event.name for msg in event_messages
            if msg.event.name in bare_kmem_names
        ]
        assert bad == [], f"Bare kmem events without prefix found: {bad}"

#Clock / timing checks

class TestClockCorrectness:
    def test_events_have_clock_snapshots(self, event_messages):
        missing = [
            msg.event.name for msg in event_messages
            if msg.default_clock_snapshot is None
        ]
        assert missing == [], f"Events missing clock snapshots: {missing}"

    def test_timestamps_are_monotonic(self, event_messages):
        timestamps = [
            msg.default_clock_snapshot.value
            for msg in event_messages
            if msg.default_clock_snapshot is not None
        ]
        for i in range(1, len(timestamps)):
            assert timestamps[i] >= timestamps[i - 1], (
                f"Non-monotonic timestamp at index {i}: "
                f"{timestamps[i]} < {timestamps[i-1]}"
            )

class TestPrioCorrectness:
    def test_sched_rt_priority_limit(self, event_messages):
            """
            Ensure that no scheduling event exceeds the maximum 
            allowed RT priority of 100.
            """
            MAX_RT_PRIO = 100
            
            for msg in event_messages:
                if msg.event.name in ["sched_switch", "sched_wakeup", "sched_process_fork"]:
                    payload = msg.event.payload_field
                    
                    prio_fields = ["prio", "prev_prio", "next_prio"]
                    
                    for field in prio_fields:
                        if field in payload:
                            prio_value = payload[field]
                            assert prio_value <= MAX_RT_PRIO, (
                                f"Priority Violation! Event '{msg.event.name}' "
                                f"found with {field}={prio_value} (Max allowed: {MAX_RT_PRIO})"
                            )
