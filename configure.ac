#;**********************************************************************;
# Copyright (c) 2015 - 2018 Intel Corporation
# Copyright (c) 2018 Fraunhofer SIT sponsored by Infineon Technologies AG
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.
#;**********************************************************************;
AC_INIT([tpm2-tss],
        [2.0.0-dev],
        [https://github.com/tpm2-software/tpm2-tss/issues],
        [],
        [https://github.com/tpm2-software/tpm2-tss])
AC_CONFIG_MACRO_DIR([m4])
${CFLAGS=""}
AC_PROG_CC
LT_INIT()
AM_INIT_AUTOMAKE([foreign
                  subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])]) #Backward compatible setting of "silent-rules"

AC_CONFIG_FILES([Makefile Doxyfile])

# propagate configure arguments to distcheck
AC_SUBST([DISTCHECK_CONFIGURE_FLAGS],[$ac_configure_args])

AC_ARG_ENABLE([unit],
            [AS_HELP_STRING([--enable-unit],
                            [build cmocka unit tests (default is no)])],
            [enable_unit=$enableval],
            [enable_unit=no])
m4_define([cmocka_min_version], [1.0])
m4_define([cmocka_err], [Unit test enabled, but cmocka missing or version requirements not met. cmocka version must be >= cmocka_min_version])
AS_IF([test "x$enable_unit" != xno],
      [PKG_CHECK_MODULES([CMOCKA],
                         [cmocka >= cmocka_min_version],
                         [AC_DEFINE([HAVE_CMOCKA],
                                    [1])],
                         [AC_MSG_ERROR([cmocka_err])])])
AM_CONDITIONAL([UNIT], [test "x$enable_unit" != xno])

# Uriparser library required by simulator TCTI library.
PKG_CHECK_MODULES([URIPARSER],[liburiparser])

AC_ARG_ENABLE([esapi],
            [AS_HELP_STRING([--enable-esapi],
                            [build the esapi layer (default is yes)])],
            [enable_esapi=$enableval],
            [enable_esapi=yes])
AS_IF([test "x$enable_esapi" != xno],
      [AC_CHECK_HEADER([gcrypt.h],
                       [],
                       [AC_MSG_ERROR([Missing required header: gcrypt.h.])])])
AS_IF([test "x$enable_esapi" != xno],
      [AC_CHECK_LIB([gcrypt],
                    [gcry_mac_open],
                    [],
                    [AC_MSG_ERROR([Missing required library: gcrypt.])])])
AM_CONDITIONAL([ESAPI], [test "x$enable_esapi" != xno])

AC_ARG_WITH([tctidefaultmodule],
            [AS_HELP_STRING([--with-tctidefaultmodule],
[The default TCTI module for ESAPI. (Default: libtss2-tcti-default.so])],
            [AC_DEFINE_UNQUOTED([ESYS_TCTI_DEFAULT_MODULE],
                                [$with_tctidefaultmodule],
                                ["The default TCTI library file"])],
            [])

AC_ARG_WITH([tctidefaultconfig],
            [AS_HELP_STRING([--with-tctidefaultconfig],
                            [The default tcti module's configuration.])],
            [AC_DEFINE_UNQUOTED([ESYS_TCTI_DEFAULT_CONFIG],
                                [$with_tctidefaultconfig],
                                ["The default TCTIs configuration string"])],
            [])

#
# udev
#
AC_ARG_WITH([udevrulesdir],
            [AS_HELP_STRING([--with-udevrulesdir=DIR],[udev rules directory])],
            [],
            [with_udevrulesdir=${libdir}/udev/rules.d])
AX_NORMALIZE_PATH([with_udevrulesdir])
AC_SUBST([udevrulesdir], [$with_udevrulesdir])
AC_ARG_WITH([udevrulesprefix],
            [AS_HELP_STRING([--with-udevrulesprefix=XY],[prefix for udev rules file])],
            [AC_SUBST([udevrulesprefix],[$with_udevrulesprefix])])
AM_CONDITIONAL(WITH_UDEVRULESPREFIX, [test -n "$with_udevrulesprefix"])
#
# simulator binary
#
AC_MSG_CHECKING([Checking for simulator binary: $with_simulatorbin])
AC_ARG_WITH([simulatorbin],
            [AS_HELP_STRING([--with-simulatorbin=tpm_server],[simulator executable])],
            [AS_IF([test \( -f "$with_simulatorbin" \) -a \( -x "$with_simulatorbin" \)],
                   [AC_MSG_RESULT([success])
                    AC_SUBST([SIMULATOR_BIN],[$with_simulatorbin])
                    AX_NORMALIZE_PATH([with_simulatorbin])
                    with_simulatorbin_set=yes],
                   [AC_MSG_ERROR([TPM simulator binary provided does not exist])])],
            [with_simulatorbin_set=no])
AM_CONDITIONAL([SIMULATOR_BIN],[test "x$with_simulatorbin_set" = "xyes"])

AS_IF([test "x$with_simulatorbin_set" == xyes],
      [PKG_CHECK_MODULES([LIBCRYPTO],[libcrypto])])

gl_LD_VERSION_SCRIPT

AX_ADD_COMPILER_FLAG([-std=c99])
AX_ADD_COMPILER_FLAG([-Wall])
AX_ADD_COMPILER_FLAG([-Wextra])
AX_ADD_COMPILER_FLAG([-Wformat-security])
AX_ADD_COMPILER_FLAG([-Werror])
AX_ADD_COMPILER_FLAG([-fstack-protector-all])
AX_ADD_COMPILER_FLAG([-fpic])
AX_ADD_COMPILER_FLAG([-fPIC])

AX_ADD_PREPROC_FLAG([-D_DEFAULT_SOURCE])
AX_ADD_PREPROC_FLAG([-D_BSD_SOURCE])
AX_ADD_PREPROC_FLAG([-D_POSIX_SOURCE])

AC_ARG_WITH([maxloglevel],
            [AS_HELP_STRING([--with-maxloglevel={none,error,warning,info,debug,trace}],
                            [sets the maximum log level (default is trace)])],
            [],
            [with_maxloglevel=trace])
AS_IF([test "x$with_maxloglevel" = "xnone"],
      AC_DEFINE_UNQUOTED([MAXLOGLEVEL], [0], ["Logging disabled"]),
AS_IF([test "x$with_maxloglevel" = "xerror"],
      AC_DEFINE_UNQUOTED([MAXLOGLEVEL], [2], ["Error log level"]),
AS_IF([test "x$with_maxloglevel" = "xwarning"],
      AC_DEFINE_UNQUOTED([MAXLOGLEVEL], [3], ["Warning log level"]),
AS_IF([test "x$with_maxloglevel" = "xinfo"],
      AC_DEFINE_UNQUOTED([MAXLOGLEVEL], [4], ["Info log level"]),
AS_IF([test "x$with_maxloglevel" = "xdebug"],
      AC_DEFINE_UNQUOTED([MAXLOGLEVEL], [5], ["Debug log level"]),
AS_IF([test "x$with_maxloglevel" = "xtrace"],
      AC_DEFINE_UNQUOTED([MAXLOGLEVEL], [6], ["Trace log level"]),
AC_MSG_ERROR([Bad value for --with-maxloglevel])))))))

AC_ARG_ENABLE([debug],
            [AS_HELP_STRING([--enable-debug],
                            [build with debug info (default is no)])],
            [enable_debug=$enableval],
            [enable_debug=no])
AS_IF([test "x$enable_debug" = "xyes"], AX_ADD_COMPILER_FLAG([-ggdb3 -Og]))
AS_IF([test "x$enable_debug" = "xno"], [AX_ADD_PREPROC_FLAG([-U_FORTIFY_SOURCE])
                                        AX_ADD_PREPROC_FLAG([-D_FORTIFY_SOURCE=2])
                                        AX_ADD_COMPILER_FLAG([-g -O2])])
AX_ADD_LINK_FLAG([-Wl,--no-undefined])
AX_ADD_LINK_FLAG([-Wl,-z,noexecstack])
AX_ADD_LINK_FLAG([-Wl,-z,now])
AX_ADD_LINK_FLAG([-Wl,-z,relro])

# work around GCC bug #53119
#   https://gcc.gnu.org/bugzilla/show_bug.cgi?id=53119
AX_ADD_COMPILER_FLAG([-Wno-missing-braces])

dnl --------- Doxy Gen -----------------------
DX_DOXYGEN_FEATURE(ON)
DX_DOT_FEATURE(OFF)
DX_HTML_FEATURE(ON)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_MAN_FEATURE(ON)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN($PACKAGE_NAME, [Doxyfile], [doc/doxy])

AX_CODE_COVERAGE

AC_OUTPUT

AC_MSG_RESULT([
    $PACKAGE_NAME $VERSION
    esapi:              $enable_esapi
    tctidefaultmodule:  $with_tctidefaultmodule
    tctidefaultconfig:  $with_tctidefaultconfig
    unit:               $enable_unit
    debug:              $enable_debug
    simulatorbin:       $with_simulatorbin
    maxloglevel:        $with_maxloglevel
    doxygen:            $DX_FLAG_doc $enable_doxygen_doc
])
    
