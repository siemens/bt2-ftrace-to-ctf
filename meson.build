# SPDX-FileCopyrightText: (C) 2025 Siemens
# SPDX-License-Identifier: MIT

project(
  'ftrace-to-ctf',
  'c',
  version : '0.1.0',
  default_options : [
    'c_std=gnu11',
    'warning_level=3',
  ]
)

glib_dep = dependency('glib-2.0')
json_glib_dep = dependency('json-glib-1.0')
uuid_dep = dependency('uuid')
traceevent_dep = dependency('libtraceevent')
tracecmd_dep = dependency('libtracecmd')
babeltrace2_dep = dependency('babeltrace2')
bt2_dep_version = babeltrace2_dep.version().split('.')
add_project_arguments(
  '-DBT2_VERSION_MINOR=' + bt2_dep_version[1],
  language : 'c'
)

project_version_parts = meson.project_version().split('.')
conf_data = configuration_data({
  'version_major': project_version_parts[0],
  'version_minor': project_version_parts[1],
  'version_patch': project_version_parts[2]
})
configure_file(input : 'src/config.h.in',
               output : 'config.h',
               configuration : conf_data)
config_inc = include_directories('.')

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
  gnu_symbol_visibility: 'hidden',
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
