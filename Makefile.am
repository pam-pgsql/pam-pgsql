ACLOCAL_AMFLAGS = -I m4

dist_doc_DATA = README CHANGELOG COPYRIGHT CREDITS sample.sql
EXTRA_DIST = autogen.sh

AM_CFLAGS = -Wall
AM_CPPFLAGS = -DSYSCONFDIR='"$(sysconfdir)"'

pammod_LTLIBRARIES = pam_pgsql.la
pam_pgsql_la_CFLAGS = $(AM_CFLAGS) $(VISIBILITY_CFLAG) $(POSTGRESQL_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)
pam_pgsql_la_LIBADD = -lpam $(POSTGRESQL_LDFLAGS) $(LIBGCRYPT_LIBS)
pam_pgsql_la_LDFLAGS = -module -export-dynamic -shared -avoid-version $(LDFLAGS_NOUNDEFINED)
pam_pgsql_la_SOURCES = \
			src/pam_pgsql.c \
			src/pam_pgsql.h \
			src/pam_pgsql_options.c \
			src/pam_pgsql_options.h \
			src/backend_pgsql.c \
			src/backend_pgsql.h \
			src/pam_get_service.c \
			src/pam_get_pass.c

if HAVE_PAM_CONV
EXTRA_PROGRAMS = authenticate chpass
endif

authenticate_LDADD = -lpam $(PAMCONVLIB)
authenticate_SOURCES = tests/authenticate.c

chpass_LDADD = -lpam $(PAMCONVLIB)
chpass_SOURCES = tests/chpass.c
