# SPDX-FileCopyrightText: (C) 2026 Siemens
# SPDX-License-Identifier: MIT

docs_option = get_option('build_docs')

if docs_option
    message('Building Doxygen documentation...')
    all_doxygen_inputs = files('Doxyfile', '../README.md')

    c_h_output = run_command('find', '../src', '-type', 'f', '-name', '*.c', '-o', '-name', '*.h', check: true).stdout().strip()
    cpp_hpp_output = run_command('find', '../src', '-type', 'f', '-name', '*.cpp', '-o', '-name', '*.hpp', check: true).stdout().strip()

    c_h_files = []
    if c_h_output != ''
        c_h_files = c_h_output.split('\n')
    endif

    cpp_hpp_files = []
    if cpp_hpp_output != ''
        cpp_hpp_files = cpp_hpp_output.split('\n')
    endif

    found_source_files = c_h_files + cpp_hpp_files

    foreach f : found_source_files
        if f != ''
            all_doxygen_inputs += f
        endif
    endforeach

    doxygen_docs = custom_target(
        'doxygen_docs',
        input: all_doxygen_inputs,
        output: 'html',
        command: ['doxygen', '@INPUT@'],
        build_by_default: false,
        install: false,
    )

    alias_target('docs', doxygen_docs)
endif
