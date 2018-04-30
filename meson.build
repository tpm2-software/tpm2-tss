project('tpm2-tss', 'c',
        version : '2.0.0-dev',
        license : 'BSD 2-clause',
        meson_version : '>= 0.41',
        default_options : [
            'c_std=c99',
            'werror=true',
            'b_lundef=true'
        ] )

################################################################################

subdir('src')
subdir('test')

################################################################################

tctidefault_c_args = []
if get_option('tctidefaultmodule') != ''
    tctidefault_c_args += [ '-DESYS_TCTI_DEFAULT_MODULE='+get_option('tctidefaultmodule') ]
endif
if get_option('tctidefaultconfig') != ''
    tctidefault_c_args += [ '-DESYS_TCTI_DEFAULT_CONFIG='+get_option('tctidefaultconfig') ]
endif

maxloglevel = get_option('maxloglevel').to_lower()
if maxloglevel == 'trace'
    add_project_arguments('-DMAXLOGLEVEL=6', language : 'c')
elif maxloglevel == 'debug'
    add_project_arguments('-DMAXLOGLEVEL=5', language : 'c')
elif maxloglevel == 'info'
    add_project_arguments('-DMAXLOGLEVEL=4', language : 'c')
elif maxloglevel == 'warning'
    add_project_arguments('-DMAXLOGLEVEL=3', language : 'c')
elif maxloglevel == 'error'
    add_project_arguments('-DMAXLOGLEVEL=2', language : 'c')
elif maxloglevel == 'none'
    add_project_arguments('-DMAXLOGLEVEL=0', language : 'c')
else
    error('No maxloglevel set.')
endif

################################################################################

cc = meson.get_compiler('c')
foreach arg : ['-Wall',
               '-Wextra',
               '-fstack-protector',
               '-fstack-protector-strong',
               '-fstack-protector-all',
               '-fPIE' ]
        if cc.has_argument(arg)
                add_project_arguments(arg, language : 'c')
        endif
endforeach

add_project_arguments('-D_DEFAULT_SOURCE',
                      '-D_BSD_SOURCE',
                      '-D_POSIX_SOURCE',
                      language : 'c')

################################################################################

libdl = cc.find_library('dl')
libgcrypt = cc.find_library('gcrypt')
liburiparser = dependency('liburiparser')
libcrypto = dependency('libcrypto')

################################################################################

tss2_headers = files('''
        include/tss2/tss2_common.h
        include/tss2/tss2_esys.h
        include/tss2/tss2_mu.h
        include/tss2/tss2_sys.h
        include/tss2/tss2_tcti.h
        include/tss2/tss2_tcti_device.h
        include/tss2/tss2_tcti_mssim.h
        include/tss2/tss2_tpm2_types.h'''.split())

install_headers(tss2_headers, subdir: 'tss2')

################################################################################

incdirs = include_directories('include/tss2', 'src', 'src/util')

libutil = static_library('util', util_sources,
               include_directories : incdirs, install : false)

libmu = shared_library('tss2-mu', mu_sources,
               include_directories : incdirs,
               link_whole : libutil,
               install : true)

libdevice = shared_library('tss2-tcti-device', device_sources,
                           include_directories : incdirs,
                           link_with : libmu,
                           install : true)

libmssim = shared_library('tss2-tcti-mssim', mssim_sources,
                          include_directories : incdirs,
                          link_with : libmu,
                          dependencies : liburiparser,
                          install : true)

libsys = shared_library('tss2-sys', sys_sources,
                        include_directories : [ incdirs,
                             include_directories('src/tss2-sys') ],
                        link_with : libmu,
                        install : true)

libesys = shared_library('tss2-esys', esys_sources,
                         include_directories : [ incdirs,
                             include_directories('src/tss2-sys',
                                                 'src/tss2-esys') ],
                         c_args: tctidefault_c_args,
                         link_with : [ libdevice, libmssim, libmu, libsys ],
                         dependencies : [ libgcrypt, libdl ],
                         install : true)

################################################################################

docdir = join_paths(get_option('datadir'), 'doc', meson.project_name())

install_data('CHANGELOG.md',
             'CONTRIBUTING.md',
             'INSTALL.md',
             'README.md',
             'RELEASE.md',
             'LICENSE',
             'MAINTAINERS',
             'doc/archandlayout.md',
             'doc/arch.md',
             'doc/coding_standard_c.md',
             'doc/logging.md',
             'doc/TSS block diagram.png',
             install_dir : docdir)

cdata = configuration_data()
cdata.set('VERSION', meson.project_version())
cdata.set('PACKAGE_NAME', meson.project_name())
cdata.set('TOP_SRCDIR', meson.source_root())
cdata.set('TOP_BUILDDIR', meson.build_root())

man_pages = []
foreach m: ['tss2-tcti-device.7',
            'Tss2_Tcti_Device_Init.3',
            'tss2-tcti-mssim.7',
            'Tss2_Tcti_Mssim_Init.3']
    man_pages += configure_file(input: 'man/'+m+'.in',
                                output: m,
                                configuration: cdata)
endforeach

man = custom_target('man',
                    output : 'man',
                    input : man_pages,
                    command : ['echo'])

if get_option('doxygen-docs')
    doxygen = find_program('doxygen', required : false)

    doxyfile = configure_file(input: 'doc/Doxyfile.in',
                              output: 'Doxyfile',
                              configuration: cdata,
                              install: false)

    html_target = custom_target('doxygen-docs',
                                build_always: true,
                                input: doxyfile,
                                output: 'html',
                                command: [doxygen, doxyfile],
                                install: true,
                                install_dir: docdir)
endif

################################################################################

if get_option('tests')

cmocka = dependency('cmocka')
#libuthash = cc.find_library('ut', libtype: 'static')

test_c_args = [ '-Wno-unused-parameter',
                '-Wno-missing-field-initializers',
                '-Wno-missing-braces' ]

libtestutil = static_library('testutil', testutil_sources,
                             include_directories : [ incdirs,
                                 include_directories('src/tss2-sys',
                                                     'src/tss2-esys') ],
                             c_args : test_c_args,
                             link_with : [ libdevice, libmssim, libmu, libsys ],
                             dependencies: [ libcrypto ])

foreach t: tests_unit
test(t[0], executable(t[0].underscorify(),
                      [ t[0]+'.c' ] + t[1],
                      include_directories : [ incdirs,
                          include_directories('src/tss2-sys'),
                          include_directories('src/tss2-esys') ],
                      c_args : t[2] + test_c_args,
                      link_with : [ libmu, libsys, libesys, libdevice, libmssim ],
                      link_whole : [ libutil, libtestutil ],
                      link_args : t[3],
                      dependencies: [ cmocka, liburiparser ] ))
endforeach

testhelperstartup = executable('test/helper/tpm_startup',
                               'test/helper/tpm_startup.c',
                               include_directories : [ incdirs,
                                   include_directories('src/tss2-sys'),
                                   include_directories('test/integration') ],
                               c_args: test_c_args,
                               link_with : [ libmu, libsys, libmssim ],
                               link_whole : [ libutil, libtestutil ],
                               dependencies: [ cmocka, liburiparser ] )

testhelperstartup = executable('test/helper/tpm_transientempty',
                               'test/helper/tpm_transientempty.c',
                               include_directories : [ incdirs,
                                   include_directories('src/tss2-sys'),
                                   include_directories('test/integration') ],
                               c_args: test_c_args,
                               link_with : [ libmu, libsys, libmssim ],
                               link_whole : [ libutil, libtestutil ],
                               dependencies: [ cmocka, liburiparser ] )

testharness = find_program('script/int-log-compiler.sh')

simulatorbin = get_option('simulatorbin')
if simulatorbin != ''
  tpmsim = find_program(simulatorbin)
  add_test_setup('sim',
                 exe_wrapper: [ testharness, '--simulator-bin='+tpmsim.path() ])
endif

foreach t: tests_integration
    tsrc = t[1]
    if (t[1] == [])
        tsrc += [ t[0]+'.c' ]
        if (t[0].startswith('test/integration/esys-'))
            tsrc += ['test/integration/main-esapi.c']
        elif (t[0].startswith('test/integration/'))
            tsrc += ['test/integration/main.c']
        endif
    endif
    test(t[0], executable(t[0].underscorify(), tsrc,
                          include_directories : [ incdirs,
                              include_directories('src/tss2-sys'),
                              include_directories('src/tss2-esys') ],
                          c_args : t[2] + test_c_args,
                          link_with : [ libmu, libsys, libesys, libdevice, libmssim ],
                          link_whole : [ libutil, libtestutil ],
                          link_args : t[3],
                          dependencies: [ libcrypto ] ) )
endforeach

endif #tests
