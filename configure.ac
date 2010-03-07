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

AC_CHECK_HEADERS_ONCE([security/pam_modules.h security/openpam.h security/pam_misc.h])
AC_CHECK_LIB([pam], [pam_get_user], [:])

AS_IF([test "x$ac_cv_header_security_pam_modules_h" = "xno" \
       -o "x$ac_cv_lib_pam_pam_get_user" = "xno"], [
  AC_MSG_ERROR([Unable to find the PAM library or the PAM header files])
])

AC_MSG_CHECKING([where to install the PAM module])
AS_IF([test "x$ac_cv_header_security_openpam_h" = "xyes"],
        dnl OpenPAM/FreeBSD installs in /usr/lib by default
        [pammoddir='$(libdir)'],
      [test "x$ac_cv_header_security_pam_misc_h" = "xyes"],
        dnl Linux-PAM uses /lib/security, assume that the user has passed
        dnl --libdir=/lib at least… this is important to get right the lib64
        dnl ABI directory
        [pammoddir='$(libdir)/security'],
      [pammoddir='$(libdir)'
       AC_MSG_WARN([Unknown PAM implementation, defaulting to something safe])
      ])
AC_MSG_RESULT([$pammoddir])
AC_SUBST([pammoddir])

dnl the two test programs use a default conversation, that is found on
dnl either libpam_misc (Linux-PAM) or libpam proper (OpenPAM); so try
dnl to be smart here.
dnl
dnl While Linux-PAM is much more widespread, check for OpenPAM first
dnl as it happened before that users mixed up the libpam_misc with the
dnl OpenPAM library by mistake.

AC_CHECK_FUNC([openpam_ttyconv], [PAMCONVLIB=-lpam], [
  AC_CHECK_LIB([pam_misc], [misc_conv], [PAMCONVLIB=-lpam_misc], [
    AC_MSG_WARN([Unable to find a compatible PAM conversation, not building tests])
  ])
])
AC_SUBST([PAMCONVLIB])
AM_CONDITIONAL([HAVE_PAM_CONV], [test "x$PAMCONVLIB" != "x"])

AX_LIB_POSTGRESQL
AS_IF([test "x$found_postgresql" != "xyes"], [
  AC_MSG_ERROR([Unable to find the PostgreSQL development files])
])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
