# SPDX-FileCopyrightText: (C) 2025 Siemens
# SPDX-License-Identifier: MIT

# Configuration for manpage version substitution
man_conf = configuration_data({
  'VERSION': meson.project_version(),
})

man_ftrace_to_ctf = configure_file(
  input : 'ftrace-to-ctf.1.in',
  output : 'ftrace-to-ctf.1',
  configuration : man_conf)

install_data(man_ftrace_to_ctf,
  install_dir : join_paths(get_option('mandir'), 'man1'))
