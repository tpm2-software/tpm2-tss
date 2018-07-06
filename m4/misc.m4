dnl ERROR_IF_NO_PROG
dnl   A quick / dirty macro to ensure that a required program / executable
dnl   is on PATH. If it is not we display an error message using AC_MSG_ERROR.
dnl $1: program name
AC_DEFUN([ERROR_IF_NO_PROG],[
    AC_CHECK_PROG([result], [$1], [yes], [no])
    AS_IF([test "x$result" != "xyes"], [
        AC_MSG_ERROR([Missing required program '$1': ensure it is installed and on PATH.])
    ])
])
