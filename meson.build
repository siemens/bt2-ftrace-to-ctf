# SPDX-FileCopyrightText: (C) 2025 Siemens
# SPDX-License-Identifier: MIT

project(
  'ftrace-to-ctf',
  'c',
  version : '0.2.0',
  meson_version : '>=1.3.0',
  default_options : [
    'c_std=gnu11',
    'warning_level=3',
  ]
)

cc = meson.get_compiler('c')

glib_dep = dependency('glib-2.0')
json_glib_dep = dependency('json-glib-1.0')
uuid_dep = dependency('uuid')
traceevent_dep = dependency('libtraceevent')
tracecmd_dep = dependency('libtracecmd')
babeltrace2_dep = dependency('babeltrace2')

tc_has_reverse_it = cc.has_function('tracecmd_iterate_events_reverse',
                                    dependencies: tracecmd_dep,
                                    required: false)
bt2_has_clock_uid = cc.has_function('bt_clock_class_set_uid',
                                    dependencies: babeltrace2_dep,
                                    required: false)
bt2_has_clock_unknown = cc.has_function('bt_clock_class_set_origin_unknown',
                                        dependencies: babeltrace2_dep,
                                        required: false)
bt2_has_trace_uid = cc.has_function('bt_trace_set_uid',
                                    dependencies: babeltrace2_dep,
                                    required: false)

project_version_parts = meson.project_version().split('.')
conf_data = configuration_data({
  'version_major': project_version_parts[0],
  'version_minor': project_version_parts[1],
  'version_patch': project_version_parts[2],
  'tracecmd_private_syms': get_option('tracecmd-internals').to_int(),
  'has_bt2_clock_uid': bt2_has_clock_uid.to_int(),
  'has_bt2_clock_unknown': bt2_has_clock_unknown.to_int(),
  'has_bt2_trace_uid': bt2_has_trace_uid.to_int(),
  'has_tracecmd_reverse_iteration': tc_has_reverse_it.to_int()
})
configure_file(input : 'src/config.h.in',
               output : 'config.h',
               configuration : conf_data)
config_inc = include_directories('.')

summary({'private libtracecmd symbols (plugin)': get_option('tracecmd-internals')}, bool_yn: true, section: 'Build Configuration')

# hidden symbols are supported from babeltrace 2.1 on:
# https://github.com/efficios/babeltrace/commit/1353b066072e6c389ff35853bac83f65597e7a6a
if babeltrace2_dep.version().version_compare('>=2.1')
  bt2_plugin_sym_vis = 'hidden'
else
  bt2_plugin_sym_vis = 'default'
endif
bt2_ftrace_plugin = shared_library('babeltrace-plugin-ftrace',
  sources: files(
    'src/bt-ftrace-logging.h',
    'src/bt-ftrace-lttng-events.c',
    'src/bt-ftrace-lttng-events.h',
    'src/bt-ftrace-plugin.c',
    'src/bt-ftrace-source.c',
    'src/bt-ftrace-source.h',
    'src/bt-ftrace-tracemeta.c',
    'src/bt-ftrace-tracemeta.h'
    ),
  c_args: ['-Wno-unused-parameter'],
  gnu_symbol_visibility: bt2_plugin_sym_vis,
  include_directories: config_inc,
  name_prefix: '',
  install_dir: get_option('libdir') / 'babeltrace2/plugins',
  install: true,
  dependencies: [
    tracecmd_dep,
    traceevent_dep,
    babeltrace2_dep,
    glib_dep,
    json_glib_dep,
    uuid_dep
  ]
)

executable('ftrace-to-ctf',
  sources: files('src/ftrace-to-ctf.c'),
  install: true,
  dependencies: [tracecmd_dep, traceevent_dep, babeltrace2_dep, json_glib_dep, uuid_dep],
  link_with: bt2_ftrace_plugin
)
