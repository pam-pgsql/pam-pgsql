#ifndef __BACKEND_PGSQL_H
#define __BACKEND_PGSQL_H

#include <libpq-fe.h>
#include <security/pam_modules.h>
#include "pam_mod_misc.h"
#include "pam_pgsql_options.h"

char * build_connect_string(struct module_options *options);
int options_valid(struct module_options *options);
PGconn * pg_connect(struct module_options *options);
PGconn * db_connect(modopt_t *options);
int expand_query (char **command, const char** values, const char *query, const char *service, const char *user, const char *passwd, const char *rhost, const char *raddr);
int pg_execParam(PGconn *conn, PGresult **res, const char *query, const char *service, const char *user, const char *passwd, const char *rhost);
int auth_verify_password(const char *service, const char *user, const char *passwd, const char *rhost, struct module_options *options);
int backend_authenticate(const char *service, const char *user, const char *passwd, const char *rhost, modopt_t *options);
char * encrypt_password(struct module_options *options, const char *pass, const char *salt);
char * password_encrypt(modopt_t *options, const char *pass, const char *salt);
char * crypt_make_salt(struct module_options *options);
char * crypt_makesalt(pw_scheme scheme);

#endif
