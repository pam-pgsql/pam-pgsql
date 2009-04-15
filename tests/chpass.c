/*
 * Sample application to change password using pam_pgsql
 *
 * William Grzybowski <william@agencialivre.com.br>
 */

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>

static struct pam_conv conv = {
    misc_conv,
    NULL
};

int main(int argc, char **argv) {

    pam_handle_t *pamh=NULL;
    int retval;
    const char *user="nobody";

    if(argc == 2) 
        user = argv[1];
	 else if(argc > 2) {
        fprintf(stderr, "Usage: chpass [username]\n");
        exit(1);
    }

    retval = pam_start("pgsql", user, &conv, &pamh);

   if(retval == PAM_SUCCESS) {
		printf("PAM started.\n");
		retval = pam_chauthtok(pamh, 0); 
	}

	printf("Changing authentication token...\n");
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
