dnl Configure template for pam_pgsql

AC_PREREQ([2.62])
AC_INIT([pam-pgsql], 0.7,[http://sourceforge.net/tracker/?func=add&group_id=62198&atid=499727], pam-pgsql)

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([Makefile.am])
AC_CONFIG_HEADERS([config.h])

AM_MAINTAINER_MODE

AM_INIT_AUTOMAKE([foreign subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

LT_INIT([disable-static])

AC_PROG_CC

dnl Checks for libraries.
AC_CHECK_HEADERS_ONCE([security/pam_modules.h])
AC_CHECK_LIB([pam], [pam_get_user], [:])

AS_IF([test "x$ac_cv_header_security_pam_modules_h" = "xno" \
       -o "x$ac_cv_lib_pam_pam_get_user" = "xno"], [
  AC_MSG_ERROR([Unable to find the PAM library or the PAM header files])
])

AC_CONFIG_FILES([Makefile])

AC_MSG_CHECKING(for PostgreSQL headers)
for d in /usr /usr/local /usr/local/pgsql; do
    test -f $d/include/libpq-fe.h && {
        AC_SUBST(PGSQL_INC)
        PGSQL_INC="-I$d/include"
        PG_DIR="$d"
        AC_MSG_RESULT($d/include)
    }
    test -f $d/include/postgresql/libpq-fe.h && {
        AC_SUBST(PGSQL_INC)
        PGSQL_INC="-I$d/include/postgresql"
        PG_DIR="$d"
        AC_MSG_RESULT($d/include/postgresql)
    }
    test -f $d/include/postgresql/8.0/libpq-fe.h && {
        AC_SUBST(PGSQL_INC)
        PGSQL_INC="-I$d/include/postgresql/8.0"
        PG_DIR="$d"
        AC_MSG_RESULT($d/include/postgresql/8.0)
    }
    test -f $d/include/pgsql/libpq-fe.h && {
        AC_SUBST(PGSQL_INC)
        PGSQL_INC="-I$d/include/pgsql"
        PG_DIR="$d"
        AC_MSG_RESULT($d/include/pgsql)
    }
done

old_LDFLAGS="$LDFLAGS"
LDFLAGS="$LDFLAGS -L$PG_DIR/lib"
AC_CHECK_LIB(pq, PQexecParams, 
    [AC_SUBST(PGSQL_LIB) 
        PGSQL_LIB="-L$PG_DIR/lib"],
    [AC_MSG_ERROR(could not determine PostgreSQL library location)])
LDFLAGS="$old_LDFLAGS"

AC_SUBST(PGSQL_LIB) 

if test "`uname`" = "Linux" >/dev/null 2>/dev/null; then
    # Debian needs this
    PAM_MISC_LD="-lpam_misc"
	 INSTALLPAM="/lib/security/"
	 AC_DEFINE([LINUX], [1], [It is a linux machine])
else
    PAM_MISC_LD=""
	 INSTALLPAM="/usr/lib/"
fi

AC_SUBST(PAM_MISC_LD)
AC_SUBST(INSTALLPAM)
AC_SUBST(DEBUG)
AC_SUBST(DEBUG_LIB)

AC_ARG_WITH(debug, 
[  --with-debug            Enable debugging routines], 
[AC_DEFINE([DEBUG], [], [Debug]) 
    AC_CHECK_LIB(efence, malloc, [DEBUG_LIB="-lefence"])
    DEBUG="-g"],
[DEBUG=""; DEBUG_LIB=""])

AC_OUTPUT
