/*
* YubiKey PAM Module
*
* Copyright (C) 2008 Ian Firns      <firnsy@securixlive.com>
* Copyright (C) 2008 SecurixLive    <dev@securixlive.com>
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
* http://www.gnu.org/copyleft/gpl.html
*/
/*
 * Copyright information for code derived from Linux-PAM unix_chkpwd.c at end of file.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "libyubipam.h"

/* Libtool defines PIC for shared objects */
#ifndef PIC
#define PAM_STATIC
#endif

/* These #defines must be present according to PAM documentation. */
#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif
#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#if defined(DEBUG_PAM) && defined(HAVE_SECURITY__PAM_MACROS_H)
#include <security/_pam_macros.h>
#else
#define D(x)			/* nothing */
#endif

#ifndef PAM_EXTERN
#ifdef PAM_STATIC
#define PAM_EXTERN static
#else
#define PAM_EXTERN extern
#endif
#endif

static int _yubi_run_helper_binary(pam_handle_t *, const char *, const char *);

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t * pamh,
		     int flags, int argc, const char** argv)
{
	int					retval, rc;
	const char			*user = NULL;
	const char			*otp = NULL;
	int					i;

	struct pam_conv		*conv;
	struct pam_message	*pmsg[1], msg[1];
	struct pam_response *resp;

    yk_ticket           tkt;
    ykdb_entry          entry;
    ykdb_h              *handle;
    
	uint8_t             tkt_private_uid_hash[32];

	uint8_t             ticket_enc_key[256];
    uint8_t             ticket_enc_hash[32];

    uint8_t             public_uid_bin[PUBLIC_UID_BYTE_SIZE];
    uint8_t             public_uid_bin_size = 0;

	uint32_t			crc;
	int					delta_use;
	int					delta_session;

	int min_pub_uid_len = 1;
	int nargs = 1;
	int silent_otp = 0;

	for (i = 0; i < argc; i++)
	{
		if (strncmp(argv[i], "silent", 6) == 0)
			silent_otp = 1;
	}

#ifdef DEBUG
	D (("called."));
	D (("flags %d argc %d", flags, argc));
	for (i = 0; i < argc; i++)
		D (("argv[%d]=%s", i, argv[i]));
	D (("silent=%d", silent_otp));
#endif

	/* obtain the user requesting authentication */
	retval = pam_get_user (pamh, &user, NULL);
	if (retval != PAM_SUCCESS)
    {
#ifdef DEBUG
		D (("get user returned error: %s", pam_strerror (pamh, retval)));
#endif
		return retval;
    }
	
#ifdef DEBUG
	D (("get user returned: %s", user));
#endif

	/* prompt for the Yubikey OTP */
	retval = pam_get_item (pamh, PAM_CONV, (const void **) &conv);
	
	if (retval != PAM_SUCCESS)
	{
#ifdef DEBUG
		D (("get conv returned error: %s", pam_strerror (pamh, retval)));
#endif
		return retval;
	}

	pmsg[0] = &msg[0];
#ifdef DEBUG
	asprintf ((char **) &msg[0].msg, "DEBUG MODE!!! Yubikey OTP: ");
#else
	asprintf ((char **) &msg[0].msg, "Yubikey OTP: ");
#endif

	if (silent_otp)
		msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
	else
		msg[0].msg_style = PAM_PROMPT_ECHO_ON;

	resp = NULL;
	retval = conv->conv (nargs, (const struct pam_message **) pmsg,
			   &resp, conv->appdata_ptr);

	free ((char *) msg[0].msg);

	if (retval != PAM_SUCCESS)
	{
#ifdef DEBUG
		D (("conv returned error: %s", pam_strerror (pamh, retval)));
#endif
		return retval;
	}

#ifdef DEBUG
	D (("conv returned: %s", resp->resp));
#endif

	otp = resp->resp;

	retval = pam_set_item(pamh, PAM_AUTHTOK, otp);
      
	if (retval != PAM_SUCCESS)
	{
#ifdef DEBUG
		D (("set_item returned error: %s", pam_strerror (pamh, retval)));
#endif
		return retval;
	}
	retval =  _yubi_run_helper_binary(pamh, otp, user);
	return retval;

}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t * pamh,
		     int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t * pamh,
		      int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}

#ifdef PAM_STATIC

struct pam_module _pam_yubikey_modstruct = {
  "pam_yubikey",
  pam_sm_authenticate,
  pam_sm_setcred,
  NULL,
  pam_sm_open_session,
  pam_sm_close_session,
  NULL
};

#endif
/*
 * verify the password of a user
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <syslog.h>
#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#define SELINUX_ENABLED is_selinux_enabled()>0
#else
#define SELINUX_ENABLED 0
#endif
#define CHKPWD_HELPER "/sbin/yubi_chkpwd"

// this code is from Linux-PAM pam_unix support.c
static int _yubi_run_helper_binary(pam_handle_t *pamh, const char *otp, const char *user)
{
    int retval, child, fds[2];
    void (*sighandler)(int) = NULL;

    D(("called."));
    /* create a pipe for the password */
    if (pipe(fds) != 0) {
	D(("could not make pipe"));
	return PAM_AUTH_ERR;
    }

#if 0
    // this code is from Linux-PAM pam_unix support.c
    if (off(UNIX_NOREAP, ctrl)) {
	/*
	 * This code arranges that the demise of the child does not cause
	 * the application to receive a signal it is not expecting - which
	 * may kill the application or worse.
	 *
	 * The "noreap" module argument is provided so that the admin can
	 * override this behavior.
	 */
	sighandler = signal(SIGCHLD, SIG_DFL);
    }
#else
	sighandler = signal(SIGCHLD, SIG_DFL);
#endif

    /* fork */
    child = fork();
    if (child == 0) {
        int i=0;
        struct rlimit rlim;
	static char *envp[] = { NULL };
	char *args[] = { NULL, NULL, NULL, NULL };

	/* XXX - should really tidy up PAM here too */

	close(0); close(1);
	/* reopen stdin as pipe */
	close(fds[1]);
	dup2(fds[0], STDIN_FILENO);

	if (getrlimit(RLIMIT_NOFILE,&rlim)==0) {
	  for (i=2; i < (int)rlim.rlim_max; i++) {
		if (fds[0] != i)
	  	   close(i);
	  }
	}

	if (SELINUX_ENABLED && geteuid() == 0) {
          /* must set the real uid to 0 so the helper will not error
	     out if pam is called from setuid binary (su, sudo...) */
	  setuid(0);
	}

	/* exec binary helper */
	args[0] = strdup(CHKPWD_HELPER);
	args[1] = x_strdup(user);

	execve(CHKPWD_HELPER, args, envp);

	/* should not get here: exit with error */
	D(("helper binary is not available"));
	exit(PAM_AUTHINFO_UNAVAIL);
    } else if (child > 0) {
	/* wait for child */
	/* if the stored password is NULL */
        int rc=0;
	if (otp != NULL) {            /* send the password to the child */
	    write(fds[1], otp, strlen(otp)+1);
	    otp = NULL;
	} else {
	    write(fds[1], "", 1);                        /* blank password */
	}
	close(fds[0]);       /* close here to avoid possible SIGPIPE above */
	close(fds[1]);
	rc=waitpid(child, &retval, 0);  /* wait for helper to complete */
	if (rc<0) {
	  pam_syslog(pamh, LOG_ERR, "unix_chkpwd waitpid returned %d: %m", rc);
	  retval = PAM_AUTH_ERR;
	} else {
	  retval = WEXITSTATUS(retval);
	}
    } else {
	D(("fork failed"));
	close(fds[0]);
 	close(fds[1]);
	retval = PAM_AUTH_ERR;
    }

    if (sighandler != SIG_ERR) {
        (void) signal(SIGCHLD, sighandler);   /* restore old signal handler */
    }

    D(("returning %d", retval));
    return retval;
}
/* ****************************************************************** *
 * Copyright (c) Jan Rêkorajski 1999.
 * Copyright (c) Andrew G. Morgan 1996-8.
 * Copyright (c) Alex O. Yuriev, 1996.
 * Copyright (c) Cristian Gafton 1996.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
