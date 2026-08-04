# SPDX-FileCopyrightText: (C) 2026 Siemens AG
# SPDX-License-Identifier: MIT

test_files = [
  'test_bt-ftrace-lttng-events.c',
  'test_bt-ftrace-sym-field.c',
  'test_bt-ftrace-utils.c',
]

common_test_deps = [
  cmocka_dep,
  tracecmd_dep,
  traceevent_dep,
  babeltrace2_dep,
  glib_dep,
  json_glib_dep,
  uuid_dep
]

test_priority_value = 10

foreach test_file : test_files
  test_name = test_file.replace('.c', '')

  test_exe = executable(test_name,
    sources: files(test_file),
    link_with: testable_lib,
    dependencies: common_test_deps,
    include_directories: config_inc
  )

  test(test_name, test_exe, priority: test_priority_value)
endforeach

if get_option('b_coverage')
  coverage_threshold = 80

  coverage_check = find_program(
    meson.project_source_root() / 'scripts' / 'coverage.sh'
  )

  test('coverage-threshold',
    coverage_check,
    args: [
      meson.project_build_root(),
      meson.project_source_root(),
      coverage_threshold.to_string(),
    ],
    priority: 1,
    timeout: 60,
    suite: 'coverage',
    is_parallel : false
  )
endif
