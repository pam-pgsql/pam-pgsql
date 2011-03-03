/*
 * PAM authentication module for PostgreSQL
 * 
 * Based in part on pam_unix.c of FreeBSD. See COPYRIGHT
 * for licensing details.
 *
 * David D.W. Downey ("pgpkeys") <david-downey@codecastle.com> et al. (see COPYRIGHT)
 * William Grzybowski <william@agencialivre.com.br>
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#define _XOPEN_SOURCE
#include <unistd.h>
#include <netdb.h>
#include <libpq-fe.h>
#include <security/pam_appl.h>

#include "backend_pgsql.h"
#include "pam_pgsql.h"
#include "pam_pgsql_options.h"

#if SUPPORT_ATTRIBUTE_VISIBILITY_DEFAULT
# define PAM_VISIBLE PAM_EXTERN __attribute__((visibility("default")))
#else
# define PAM_VISIBLE PAM_EXTERN
#endif

/* public: authenticate user */
PAM_VISIBLE int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	modopt_t *options = NULL;
	const char *user, *password, *rhost;
	int rc;
	PGresult *res;
	PGconn *conn;	

	user = NULL; password = NULL; rhost = NULL;

	if ((rc = pam_get_item(pamh, PAM_RHOST, (const void **)&rhost)) == PAM_SUCCESS) {

		if ((rc = pam_get_user(pamh, &user, NULL)) == PAM_SUCCESS) {

			if ((options = mod_options(argc, argv)) != NULL) {

				DBGLOG("attempting to authenticate: %s, %s", user, options->query_auth);
				if ((rc = pam_get_pass(pamh, PAM_AUTHTOK, &password, PASSWORD_PROMPT, options->std_flags)) == PAM_SUCCESS) {

					if ((rc = backend_authenticate(pam_get_service(pamh), user, password, rhost, options)) == PAM_SUCCESS) {
						if ((password == 0 || *password == 0) && (flags & PAM_DISALLOW_NULL_AUTHTOK)) {
							rc = PAM_AUTH_ERR; 
						} else {
							SYSLOG("(%s) user %s authenticated.", pam_get_service(pamh), user);
						}

					} else {

                        char* rhost = NULL;
                        if (pam_get_item(pamh, PAM_RHOST, (void *) &rhost) == PAM_SUCCESS) {
                            SYSLOG("couldn't authenticate user %s (%s)", user, rhost);
                        } else {
                            SYSLOG("couldn't authenticate user %s", user);
                        }

					}

				} else {

					SYSLOG("couldn't get pass");

				}
			}
		}
	}
	
	if (rc == PAM_SUCCESS) {
		if (options->query_auth_succ) {
			if ((conn = db_connect(options))) {
				pg_execParam(conn, &res, options->query_auth_succ, pam_get_service(pamh), user, password, rhost);
				PQclear(res);
				PQfinish(conn);
			}
		}
	} else {
		if (options->query_auth_fail) {
			if ((conn = db_connect(options))) {
				pg_execParam(conn, &res, options->query_auth_fail, pam_get_service(pamh), user, password, rhost);
				PQclear(res);
				PQfinish(conn);
			}
		}
	}

	//free_mod_options(options);
	return rc;
}

/* public: check if account has expired, or needs new password */
PAM_VISIBLE int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                            const char **argv)
{
	modopt_t *options = NULL;
	const char *user, *rhost;
	int rc = PAM_AUTH_ERR;
	PGconn *conn;
	PGresult *res;

	user = NULL; rhost = NULL;

	if ((options = mod_options(argc, argv)) != NULL) {

		/* query not specified, just succeed. */
		if (options->query_acct == NULL) {
			//free_module_options(options);
			return PAM_SUCCESS;
		}

		if ((rc = pam_get_item(pamh, PAM_RHOST, (const void **)&rhost)) == PAM_SUCCESS) {
			if((rc = pam_get_user(pamh, &user, NULL)) == PAM_SUCCESS) {
				if(!(conn = db_connect(options))) {
					rc = PAM_AUTH_ERR;
				} else {
					DBGLOG("query: %s", options->query_acct);
					rc = PAM_AUTH_ERR;
					if(pg_execParam(conn, &res, options->query_acct, pam_get_service(pamh), user, NULL, rhost) == PAM_SUCCESS) {
						if (PQntuples(res) == 1 &&
						    PQnfields(res) >= 2 && PQnfields(res) <= 3) {
							char *expired_db = PQgetvalue(res, 0, 0);
							char *newtok_db = PQgetvalue(res, 0, 1);
							rc = PAM_SUCCESS;
							if (PQnfields(res)>=3) {
								char *nulltok_db = PQgetvalue(res, 0, 2);
								if ((!strcmp(nulltok_db, "t")) && (flags & PAM_DISALLOW_NULL_AUTHTOK))
									rc = PAM_NEW_AUTHTOK_REQD;
							}
							if (!strcmp(newtok_db, "t"))
								rc = PAM_NEW_AUTHTOK_REQD;
							if (!strcmp(expired_db, "t"))
								rc = PAM_ACCT_EXPIRED;
						} else {
							DBGLOG("query_acct should return one row and two or three columns");
							rc = PAM_PERM_DENIED;
						}
						PQclear(res);
					}
					PQfinish(conn);
				}
			}
		}
	}

	//free_module_options(options);
	return rc;
}

/* public: change password */
PAM_VISIBLE int
pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	modopt_t *options = NULL;
	int rc;
	const char *user, *pass, *newpass, *rhost;
	const void *oldtok;
	char *newpass_crypt;
	PGconn *conn;
	PGresult *res;

	user = NULL; pass = NULL; newpass = NULL; rhost = NULL; newpass_crypt = NULL;

	if ((options = mod_options(argc, argv)) != NULL) {
		if ((rc = pam_get_item(pamh, PAM_RHOST, (const void **)&rhost)) == PAM_SUCCESS) 
			rc = pam_get_user(pamh, &user, NULL);
	} else
		rc = 1;

	if ((rc == PAM_SUCCESS) && (flags & PAM_PRELIM_CHECK)) {
		if (getuid() != 0) {
			if ((rc = pam_get_pass(pamh, PAM_OLDAUTHTOK, &pass, PASSWORD_PROMPT, options->std_flags)) == PAM_SUCCESS) {
				rc = backend_authenticate(pam_get_service(pamh), user, pass, rhost, options);
			} else {
				SYSLOG("could not retrieve password from '%s'", user);
			}
		} else {
			rc = PAM_SUCCESS;
		}
	} else if ((rc == PAM_SUCCESS) && (flags & PAM_UPDATE_AUTHTOK)) {

		/* only try to check old password if user is not root */
		pass = newpass = NULL;
		if (getuid() != 0) {

			if ((rc = pam_get_item(pamh, PAM_OLDAUTHTOK, &oldtok)) == PAM_SUCCESS) {
				pass = (const char*) oldtok;
				if ((rc = backend_authenticate(pam_get_service(pamh), user, pass, rhost, options)) != PAM_SUCCESS) {
					SYSLOG("(%s) user '%s' not authenticated.", pam_get_service(pamh), user);
				}
			} else {
				SYSLOG("could not retrieve old token");
			}

		} else {
			rc = PAM_SUCCESS;
		}

		if (rc == PAM_SUCCESS) {

			if ((rc = pam_get_confirm_pass(pamh, &newpass, PASSWORD_PROMPT_NEW, PASSWORD_PROMPT_CONFIRM, options->std_flags)) == PAM_SUCCESS) {
				if((newpass_crypt = password_encrypt(options, user, newpass, NULL))) {
					if(!(conn = db_connect(options))) {
						rc = PAM_AUTHINFO_UNAVAIL;
					}
					if (rc == PAM_SUCCESS) {
						DBGLOG("query: %s", options->query_pwd);
						if(pg_execParam(conn, &res, options->query_pwd, pam_get_service(pamh), user, newpass_crypt, rhost) != PAM_SUCCESS) {
							rc = PAM_AUTH_ERR;
						} else {
							SYSLOG("(%s) password for '%s' was changed.", pam_get_service(pamh), user);
							PQclear(res);
						}
						PQfinish(conn);
					}
					free (newpass_crypt);
				} else {
					rc = PAM_BUF_ERR;
				}
			} else {
				SYSLOG("could not retrieve new authentication tokens");
			}
		}
	}
	//free_module_options(options);
	if (flags & (PAM_PRELIM_CHECK | PAM_UPDATE_AUTHTOK))
		return rc;
	else
		return PAM_AUTH_ERR;

}

/* public: just succeed. */
PAM_VISIBLE int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

PAM_VISIBLE int
pam_sm_open_session(pam_handle_t *pamh, int flags,
            int argc, const char **argv)
{
	modopt_t *options = NULL;
	const char *user, *rhost;
	int rc;
	PGresult *res;
	PGconn *conn;

	user = NULL; rhost = NULL;

	if ((options = mod_options(argc, argv)) != NULL) {

		if (options->query_session_open) {

			if ((rc = pam_get_item(pamh, PAM_RHOST, (const void **)&rhost)) == PAM_SUCCESS) {

				if ((rc = pam_get_user(pamh, &user, NULL)) == PAM_SUCCESS) {
					DBGLOG("Session opened for user: %s", user);
					if ((conn = db_connect(options))) {
						pg_execParam(conn, &res, options->query_session_open, pam_get_service(pamh), user, NULL, rhost);
						PQclear(res);
						PQfinish(conn);
					}
				}
			}
		}
	///free_module_options(options);
	}

	return (PAM_SUCCESS);

}

PAM_VISIBLE int
pam_sm_close_session(pam_handle_t *pamh, int flags,
            int argc, const char *argv[])
{
	modopt_t *options = NULL;
	const char *user, *rhost;
	int rc;
	PGresult *res;
	PGconn *conn;

	user = NULL; rhost = NULL;

	if ((options = mod_options(argc, argv)) != NULL) {

		if (options->query_session_close) {

			if ((rc = pam_get_item(pamh, PAM_RHOST, (const void **)&rhost)) == PAM_SUCCESS) {

				if ((rc = pam_get_user(pamh, &user, NULL)) == PAM_SUCCESS) {
					DBGLOG("Session opened for user: %s", user);
					if ((conn = db_connect(options))) {
                          pg_execParam(conn, &res, options->query_session_close, pam_get_service(pamh), user, NULL, rhost);
                          PQclear(res);
                          PQfinish(conn);
					}
				}
			}
		}
	//free_module_options(options);
	}

	return (PAM_SUCCESS);

}
