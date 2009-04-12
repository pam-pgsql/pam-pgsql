/* 
 * Copyright (c) 2000. Leon Breedt, , Copyright (c) 2002 David D.W. Downey
 * Modified FreeBSD version 
 */
/*-
 * Copyright 1998 Juniper Networks, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$FreeBSD: src/lib/libpam/libpam/pam_mod_misc.h,v 1.1.1.1 1998/11/18 01:44:37 jdp Exp $
 */

/* $Id: pam_mod_misc.h,v 1.3 2000/06/25 09:58:40 ljb Exp $ */
#ifndef PAM_MOD_MISC_H
#define PAM_MOD_MISC_H

#include <sys/cdefs.h>

/* Options */
#define PAM_OPT_DEBUG			0x01
#define PAM_OPT_NO_WARN			0x02
#define PAM_OPT_USE_FIRST_PASS		0x04
#define	PAM_OPT_TRY_FIRST_PASS		0x08
#define PAM_OPT_USE_MAPPED_PASS		0x10
#define PAM_OPT_ECHO_PASS		0x20
#define PAM_OPT_TRY_OLDAUTH		0x40
#define PAM_OPT_USE_OLDAUTH		0x80


typedef enum {
    PW_CLEAR = 1, 
    PW_MD5,
    PW_CRYPT,
    PW_CRYPT_MD5,
    PW_CRYPT_SHA1
} pw_scheme;

struct module_options {
/*new*/
    char *pg_conn_str;
    char *auth_query;
    char *auth_succ_query;
    char *auth_fail_query;
    char *acct_query;
    char *pwd_query;
    char *session_open_query;
    char *session_close_query;
/*old*/
    char *database;
    char *table;
    char *db_host;
    char *db_user;
    char *db_port;
    char *db_timeout;
    char *db_password;
    char *user_column;
    char *pwd_column;
    char *expired_column;
    char *newtok_column;
    char *config_file;
    pw_scheme pw_type;
    int debug;
    int std_flags;
};


__BEGIN_DECLS
int  pam_get_pass(pam_handle_t *, int, const char **, const char *, int);
int  pam_get_confirm_pass(pam_handle_t *, const char **, const char *,  
        const char *, int);
int  pam_std_option(struct module_options  *, const char *);
const char *pam_get_service(pam_handle_t *pamh);
__END_DECLS

#endif
