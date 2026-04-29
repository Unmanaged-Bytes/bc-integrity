# SPDX-License-Identifier: MIT

project('bc-integrity', 'c',
  version : 'rolling',
  license : 'MIT',
  default_options : [
    'c_std=c11',
    'warning_level=3',
    'werror=true',
    'optimization=3',
    'default_library=static',
  ],
)

cc = meson.get_compiler('c')

extra_c_args = [
  '-pedantic',
  '-Wconversion',
  '-Wshadow',
  '-Wformat=2',
]

extra_c_args += '-D_GNU_SOURCE'

foreach arg : extra_c_args
  if cc.has_argument(arg)
    add_project_arguments(arg, language : 'c')
  endif
endforeach

lto_c_args = []
lto_link_args = []
if get_option('buildtype') in ['release', 'minsize']
  arch_value = get_option('arch')
  if arch_value == ''
    arch_value = 'x86-64-v3'
  endif

  add_project_arguments(
    '-march=' + arch_value,
    '-funroll-loops',
    '-fomit-frame-pointer',
    '-ffunction-sections',
    '-fdata-sections',
    language : 'c',
  )
  add_project_link_arguments('-Wl,--gc-sections', language : 'c')
endif

bc_core_dep        = dependency('bc-core')
bc_allocators_dep  = dependency('bc-allocators')
bc_containers_dep  = dependency('bc-containers')
bc_concurrency_dep = dependency('bc-concurrency')
bc_io_dep          = dependency('bc-io')
bc_runtime_dep     = dependency('bc-runtime')
bc_hrbl_dep        = dependency('bc-hrbl')
xxhash_dep         = dependency('libxxhash', version : '>=0.8.0')

bc_integrity_deps = [
  bc_core_dep,
  bc_allocators_dep,
  bc_containers_dep,
  bc_concurrency_dep,
  bc_io_dep,
  bc_runtime_dep,
  bc_hrbl_dep,
]

liburing_dep = dependency('liburing', version : '>=2.5', required : true)
bc_integrity_deps += liburing_dep
add_project_arguments('-DBC_INTEGRITY_HAVE_IO_URING=1', language : 'c')

bc_integrity_internal_inc = include_directories('include/internal')

subdir('src')

if get_option('tests')
  subdir('tests')
endif

if get_option('fuzzing')
  subdir('fuzzing')
endif
