dnl Configure template for pam_pgsql

AC_PREREQ([2.63])
AC_INIT([pam-pgsql], 0.7,[http://sourceforge.net/tracker/?func=add&group_id=62198&atid=499727], pam-pgsql)

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([Makefile.am])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([foreign subdir-objects 1.11])
AM_SILENT_RULES([yes])
AM_MAINTAINER_MODE

LT_INIT([disable-static])

AC_PROG_CC

dnl Make sure that we won't have undefined symbols, when we can
dnl actually make sure of that (it's not possible on all operating
dnl systems).
CC_NOUNDEFINED

dnl Checks for libraries.
AC_SEARCH_LIBS([crypt], [c crypt])

AC_CHECK_HEADERS_ONCE([security/pam_modules.h])
AC_CHECK_LIB([pam], [pam_get_user], [:])

AS_IF([test "x$ac_cv_header_security_pam_modules_h" = "xno" \
       -o "x$ac_cv_lib_pam_pam_get_user" = "xno"], [
  AC_MSG_ERROR([Unable to find the PAM library or the PAM header files])
])

dnl the two test programs use a default conversation, that is found on
dnl either libpam_misc (Linux-PAM) or libpam proper (OpenPAM); so try
dnl to be smart here.
dnl
dnl While Linux-PAM is much more widespread, check for OpenPAM first
dnl as it happened before that users mixed up the libpam_misc with the
dnl OpenPAM library by mistake.

AC_CHECK_HEADERS([security/openpam.h security/pam_misc.h], [break;])
AC_CHECK_FUNC([openpam_ttyconv], [PAMCONVLIB=-lpam], [
  AC_CHECK_LIB([pam_misc], [misc_conv], [PAMCONVLIB=-lpam_misc], [
    AC_MSG_WARN([Unable to find a compatible PAM conversation, not building tests])
  ])
])
AC_SUBST([PAMCONVLIB])
AM_CONDITIONAL([HAVE_PAM_CONV], [test "x$PAMCONVLIB" != "x"])

AC_CHECK_HEADERS_ONCE([libpq-fe.h])
AC_CHECK_LIB([pq], [PQexecParams], [:])

AS_IF([test "x$ac_cv_header_libpq_fe_h" = "xno" \
       -o "x$ac_cv_lib_pq_PQexecParams" = "xno"], [
  AC_MSG_ERROR([Unable to find the PostgreSQL library or the PostgreSQL header files])
])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
