;**********************************************************************;
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
        [2.1.2_rc0],
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

AC_ARG_ENABLE([esapi],
            [AS_HELP_STRING([--enable-esapi],
                            [build the esapi layer (default is yes)])],
            [enable_esapi=$enableval],
            [enable_esapi=yes])

AM_CONDITIONAL(ESAPI, test "x$enable_esapi" = "xyes")

AC_ARG_ENABLE([tcti-device-async],
    AS_HELP_STRING([--enable-tcti-device-async],
	           [Enable asynchronus operation on TCTI device
		    (note: This needs to be supported by the kernel driver). default is no]),
    [enable_tcti_device_async=$enableval],
    [enable_tcti_device_async=no])
AS_IF([test "x$enable_tcti_device_async" = "xyes"],
	AC_DEFINE([TCTI_ASYNC],[1]))

AC_ARG_WITH([crypto],
            [AS_HELP_STRING([--with-crypto={gcrypt,ossl}],
                            [sets the ESAPI crypto backend (default is gcrypt)])],
            [],
            [with_crypto=gcrypt])

AM_CONDITIONAL(ESYS_OSSL, test "x$with_crypto" = "xossl")
AM_CONDITIONAL(ESYS_GCRYPT, test "x$with_crypto" = "xgcrypt")

AS_IF([test "x$with_crypto" != "xgcrypt"],
    AS_IF([test "x$with_crypto" != "xossl"],
          AC_MSG_ERROR([Bad value for --with-crypto $with_crypto])))

AS_IF([test "x$enable_esapi" != xno -a "x$with_crypto" = "xgcrypt"],
      [AC_CHECK_HEADER([gcrypt.h],
                       [],
                       [AC_MSG_ERROR([Missing required header: gcrypt.h.])])])

AS_IF([test "x$enable_esapi" != xno -a "x$with_cryptor" = "xgcrypt"],
      [AC_CHECK_LIB([gcrypt],
                    [gcry_mac_open],
                    [],
                    [AC_MSG_ERROR([Missing required library: gcrypt.])])])

AS_IF([test "x$enable_esapi" != xno -a "x$with_crypto" = "xossl"],
      [AC_CHECK_HEADER([openssl/ssl.h],
                       [],
                       [AC_MSG_ERROR([Missing required header: openssl/ssl.h.])])])

AS_IF([test "x$enable_esapi" != xno -a "x$with_crypto" = "xossl"],
    AC_CHECK_LIB(ssl, OPENSSL_init_ssl, [FOUND_SSL_LIB="yes"]))

AS_IF([test "x$enable_esapi" != xno -a "x$with_crypto" = "xossl"],
    AC_CHECK_LIB(crypto, CRYPTO_new_ex_data, [], [AC_MSG_ERROR([library 'crypto' is required for OpenSSL])]))

AC_ARG_WITH([tctidefaultmodule],
            [AS_HELP_STRING([--with-tctidefaultmodule],
[The default TCTI module for ESAPI. (Default: libtss2-tcti-default.so])],
            [AC_DEFINE_UNQUOTED([ESYS_TCTI_DEFAULT_MODULE],
                                ["$with_tctidefaultmodule"],
                                ["The default TCTI library file"])],
            [])

AC_ARG_WITH([tctidefaultconfig],
            [AS_HELP_STRING([--with-tctidefaultconfig],
                            [The default tcti module's configuration.])],
            [AC_DEFINE_UNQUOTED([ESYS_TCTI_DEFAULT_CONFIG],
                                ["$with_tctidefaultconfig"],
                                ["The default TCTIs configuration string"])],
            [])

AC_ARG_ENABLE([tcti-device],
            [AS_HELP_STRING([--enable-tcti-device],
                            [build the tcti-device module (default is yes)])],
            [enable_tcti_device=$enableval],
            [enable_tcti_device=yes])
AM_CONDITIONAL([ENABLE_TCTI_DEVICE], [test "x$enable_tcti_device" != xno])

AC_ARG_ENABLE([tcti-mssim],
            [AS_HELP_STRING([--enable-tcti-mssim],
                            [build the tcti-mssim module (default is yes)])],
            [enable_tcti_mssim=$enableval],
            [enable_tcti_mssim=yes])
AM_CONDITIONAL([ENABLE_TCTI_MSSIM], [test "x$enable_tcti_mssim" != xno])

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
# enable integration tests and check for simulator binary
#
AC_ARG_ENABLE([integration],
    [AS_HELP_STRING([--enable-integration],
        [build and execute integration tests (default is no)])],
    [enable_integration=$enableval],
    [enable_integration=no])
AS_IF([test "x$enable_integration" = "xyes"],
      [ERROR_IF_NO_PROG([tpm_server])
       ERROR_IF_NO_PROG([netstat])
       ERROR_IF_NO_PROG([ps])
       ERROR_IF_NO_PROG([echo])
       ERROR_IF_NO_PROG([kill])
       ERROR_IF_NO_PROG([nohup])
       ERROR_IF_NO_PROG([sleep])
       ERROR_IF_NO_PROG([cat])
       ERROR_IF_NO_PROG([realpath])
       ERROR_IF_NO_PROG([dirname])
       ERROR_IF_NO_PROG([basename])
       ERROR_IF_NO_PROG([mktemp])
       ERROR_IF_NO_PROG([od])
       ERROR_IF_NO_PROG([awk])
       ERROR_IF_NO_PROG([expr])
       ERROR_IF_NO_PROG([grep])
       ERROR_IF_NO_PROG([env])
       ERROR_IF_NO_PROG([rm])
       PKG_CHECK_MODULES([LIBCRYPTO],[libcrypto])
       AC_CHECK_HEADER(uthash.h, [], [AC_MSG_ERROR([Can not find uthash.h. Please install uthash-dev])])
       AS_IF([test "x$enable_tcti_mssim" = xno],
              AC_MSG_ERROR([Integration tests can not be enabled without the TCTI_MSSIM module]))
       AC_SUBST([ENABLE_INTEGRATION], [$enable_integration])])
AM_CONDITIONAL([ENABLE_INTEGRATION],[test "x$enable_integration" = "xyes"])

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

AC_SUBST([PATH])

# work around GCC bug #53119
#   https://gcc.gnu.org/bugzilla/show_bug.cgi?id=53119
AX_ADD_COMPILER_FLAG([-Wno-missing-braces])

dnl ---------  Physical TPM device -----------------------

AC_ARG_WITH([ptpm],
            [AS_HELP_STRING([--with-ptpm=<device>],[TPM device])],
            [AS_IF([test \( -w "$with_ptpm" \)  -a \( -r "$with_ptpm" \)],
                   [AC_MSG_RESULT([success])
                    AC_SUBST([PTPM],[$with_ptpm])
                    AX_NORMALIZE_PATH([with_ptpm])
                    with_ptpm_set=yes],
                   [AC_MSG_ERROR([TPM device provided does not exist or is not writable])])],
            [with_ptpm_set=no])
AM_CONDITIONAL([PTPM],[test "x$with_ptpm_set" = "xyes"])

AC_ARG_WITH([ptpmtests],
            [AS_HELP_STRING([--with-ptpmtests=<case>],[Comma-separated values of possible tests: destructive,mandatory,optional] default is mandatory)],
            [AS_IF([test "x" ==  x$(echo $with_ptpmtests | sed 's/destructive//g'  | sed 's/mandatory//g'  | sed 's/optional//g' | sed 's/,//g') ],
                   [AC_MSG_RESULT([success])
                    with_ptpmtests_set=yes],
                   [AC_MSG_ERROR([Illegal test type for pTPM tests.])])],
            [with_ptpmtests="mandatory"])

if echo $with_ptpmtests | grep destructive > /dev/null; then
    enable_ptpm_destructive="yes"
fi
AM_CONDITIONAL([PTPMDESTRUCTIVE],[test "x$enable_ptpm_destructive" = "xyes"])

if echo $with_ptpmtests | grep optional > /dev/null; then
    enable_ptpm_optional="yes"
fi
AM_CONDITIONAL([PTPMOPTIONAL],[test "x$enable_ptpm_optional" = "xyes"])

if echo $with_ptpmtests | grep mandatory > /dev/null; then
    enable_ptpm_mandatory="yes"
fi
AM_CONDITIONAL([PTPMMANDATORY],[test "x$enable_ptpm_mandatory" = "xyes"])

AM_CONDITIONAL([TESTPTPM],[test "x$with_ptpm_set" = "xyes" -a "x$with_ptpm_set" = "xyes"])

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
DX_INIT_DOXYGEN($PACKAGE_NAME, [Doxyfile], [doc/doxygen])
AM_CONDITIONAL(DOXYMAN, [test $DX_FLAG_man -eq 1])

AX_CODE_COVERAGE

AC_OUTPUT

AM_COND_IF([ENABLE_TCTI_DEVICE], [],
           [AM_COND_IF([ENABLE_TCTI_MSSIM], [],
                       [AC_MSG_WARN("No build-in TCTI module enabled")])])

AC_MSG_RESULT([
    $PACKAGE_NAME $VERSION
    esapi:              $enable_esapi
    tctidefaultmodule:  $with_tctidefaultmodule
    tctidefaultconfig:  $with_tctidefaultconfig
    unit:               $enable_unit
    debug:              $enable_debug
    maxloglevel:        $with_maxloglevel
    doxygen:            $DX_FLAG_doc $enable_doxygen_doc
    tcti-device-async:  $enable_tcti_device_async
])
