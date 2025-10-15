project('xdp-example', 'c', version: '0.1.0')

compiler = meson.get_compiler('c')
if compiler.get_id() != 'clang'
    error('Clang compiler is required')
endif

subdir('af-xdp')