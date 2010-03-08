/*
 * PAM authentication module for PostgreSQL
 * 
 * Based in part on pam_unix.c of FreeBSD. See COPYRIGHT
 * for licensing details.
 *
 * David D.W. Downey ("pgpkeys") <david-downey@codecastle.com> et al. (see COPYRIGHT)
 * William Grzybowski <william@agencialivre.com.br>
 */


#ifndef __PAM_PGSQL_H
#define __PAM_PGSQL_H

#include "backend_pgsql.h"

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_PASSWORD
#include <security/pam_modules.h>

#define PASSWORD_PROMPT         "Password: "
#define PASSWORD_PROMPT_NEW	    "New password: "
#define PASSWORD_PROMPT_CONFIRM "Confirm new password: "

#include <syslog.h>

#define DBGLOG(x...)  if(options->debug) {                          \
                          openlog("PAM_pgsql", LOG_PID, LOG_AUTH);  \
                          syslog(LOG_DEBUG, ##x);                   \
                          closelog();                               \
                      }
#define SYSLOG(x...)  do {                                          \
                          openlog("PAM_pgsql", LOG_PID, LOG_AUTH);  \
                          syslog(LOG_INFO, ##x);                    \
                          closelog();                               \
                      } while(0);

#endif
