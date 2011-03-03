#ifndef __BACKEND_PGSQL_H
#define __BACKEND_PGSQL_H

#include <libpq-fe.h>
#include <security/pam_modules.h>
#include "pam_pgsql_options.h"

PGconn * db_connect(modopt_t *options);
int pg_execParam(PGconn *conn, PGresult **res, const char *query, const char *service, const char *user, const char *passwd, const char *rhost);
int backend_authenticate(const char *service, const char *user, const char *passwd, const char *rhost, modopt_t *options);
char * password_encrypt(modopt_t *options, const char *user, const char *pass, const char *salt);

#endif
