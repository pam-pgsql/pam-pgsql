#AM_CFLAGS = -Wall -pedantic
AM_CFLAGS = -Wall

lib_LTLIBRARIES = pam_pgsql.la
#pam_pgsql_so_LIBRARIES =  @PGSQL_LIB@ @DEBUG_LIB@ @MHASH_LIB@
#pam_pgsql_sodir = @moduledir@
#pam_pgsql_la_LBADD = -lpam -lpq @PAM_MISC_LD@ @MHASH_LD@ 
pam_pgsql_la_LIBADD = -lpam -lpq @PAM_MISC_LD@ @MHASH_LD@ 
pam_pgsql_la_LDFLAGS = -module -export-dynamic $(LDFLAGS)
pam_pgsql_la_SOURCES = \
							  pam_pgsql.c \
							  pam_pgsql.h \
							  pam_pgsql_options.c \
							  pam_pgsql_options.h \
							  backend_pgsql.c \
							  backend_pgsql.h \
							  pam_get_service.c \
							  pam_get_pass.c

