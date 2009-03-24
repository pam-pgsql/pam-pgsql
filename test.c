/*
 * Sample application to test the module
 */

/* $Id: test.c,v 1.3 2000/06/25 10:01:41 ljb Exp $ */
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>

static struct pam_conv conv = {
    misc_conv,
    NULL
};

int main(int argc, char *argv[])
{
    pam_handle_t *pamh=NULL;
    int retval;
    const char *user="nobody";

    if(argc == 2) {
        user = argv[1];
    }

    if(argc > 2) {
        fprintf(stderr, "Usage: check_user [username]\n");
        exit(1);
    }

    retval = pam_start("pgsql", user, &conv, &pamh);

    if(retval == PAM_SUCCESS)
        printf("PAM started.\n");

    if (retval == PAM_SUCCESS)
        retval = pam_authenticate(pamh, 0);    /* is user really user? */

    if(retval == PAM_SUCCESS)
        printf("Authentication succeeded, checking access.\n");
    else 
        printf("Authentication failed: %s\n", pam_strerror(pamh, retval));

    if (retval == PAM_SUCCESS)
        retval = pam_acct_mgmt(pamh, 0);       /* permitted access? */

    if(retval == PAM_SUCCESS)
        printf("Access permitted.\n");
    else 
        printf("Access denied: %s\n", pam_strerror(pamh, retval));

    /* lets try print password */
    printf("Changing authentication token...\n");
    retval = pam_chauthtok(pamh, 0); 
    if(retval != PAM_SUCCESS) {
        printf("Failed: %s\n", pam_strerror(pamh, retval));
    } else {
        printf("Token changed.\n");
    }

    /* This is where we have been authorized or not. */
    if (pam_end(pamh,retval) != PAM_SUCCESS) {     /* close Linux-PAM */
        pamh = NULL;
        fprintf(stderr, "check_user: failed to release authenticator\n");
        exit(1);
    }

    return ( retval == PAM_SUCCESS ? 0:1 );       /* indicate success */
}
