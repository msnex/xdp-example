deps = [['libbpf'], ['libxdp']]

xdp_deps = []

foreach libs : deps
    dep = dependency(libs, required: true)
    xdp_deps += dep
endforeach

executable(
    'xdpsock',
    'xdpsock.c',
    dependencies: xdp_deps,
    install: true,
    install_dir: get_option('bindir'),
)