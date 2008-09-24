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
*
*
* Description:
*   This program is designed to run setuid(root) or with sufficient privilege
* to read all of the unix password databases. It is designed to provide a
* mechanism for the current user (defined by this process' uid) to verify
* their own password.
*
*   The password is read from the standard input. The exit status of this
* program indicates whether the user is authenticated or not.
*
* 
* Acknowlegements:
*   1. This code is derived from the works of Andrew G. Morgan, 1996 in the
*      Linux-PAM project, specfically support.c
*   2. This addition was intiated by Geoff Hoff
*
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

#include <syslog.h>
#include <unistd.h>
#include <pwd.h>
#include <signal.h>

#ifdef WITH_SELINUX
#include <selinux/selinux.h>
#define SELINUX_ENABLED (selinux_enabled!=-1 ? selinux_enabled : (selinux_enabled=is_selinux_enabled()>0))
static security_context_t prev_context=NULL;
static int selinux_enabled=-1;
#else
#define SELINUX_ENABLED 0
#endif

#define MAXPASS		200	/* the maximum length of a password */

#include <security/_pam_types.h>

int _yubi_verify_password(char *, char *);

/* syslogging function for errors and other information */
#if defined(DEBUG) && defined(HAVE_SECURITY__PAM_MACROS_H)
#include <security/_pam_macros.h>
#else
#define D(x)			/* nothing */
#endif

static void _log_err(int err, const char *format,...)
{
	va_list				args;

	va_start(args, format);
	openlog("yk_chkpwd", LOG_CONS | LOG_PID, LOG_AUTHPRIV);
	vsyslog(err, format, args);
	va_end(args);
	closelog();
}

static void su_sighandler(int sig)
{
#ifndef SA_RESETHAND
	/* emulate the behaviour of the SA_RESETHAND flag */
	if ( sig == SIGILL || sig == SIGTRAP || sig == SIGBUS || sig = SIGSERV )
		signal(sig, SIG_DFL);
#endif
	if (sig > 0)
	{
		_log_err(LOG_NOTICE, "caught signal %d.", sig);
		exit(sig);
	}
}

static void setup_signals(void)
{
	struct sigaction	action;	/* posix signal structure */

	/*
	 * Setup signal handlers
	 */
	(void) memset((void *) &action, 0, sizeof(action));
	action.sa_handler = su_sighandler;
#ifdef SA_RESETHAND
	action.sa_flags = SA_RESETHAND;
#endif
	(void) sigaction(SIGILL, &action, NULL);
	(void) sigaction(SIGTRAP, &action, NULL);
	(void) sigaction(SIGBUS, &action, NULL);
	(void) sigaction(SIGSEGV, &action, NULL);
	action.sa_handler = SIG_IGN;
	action.sa_flags = 0;
	(void) sigaction(SIGTERM, &action, NULL);
	(void) sigaction(SIGHUP, &action, NULL);
	(void) sigaction(SIGINT, &action, NULL);
	(void) sigaction(SIGQUIT, &action, NULL);
}


static char *getuidname(uid_t uid)
{
	struct passwd		*pw;
	static char			username[32];

	pw = getpwuid(uid);
	if (pw == NULL)
		return NULL;

	strncpy(username, pw->pw_name, sizeof(username));
	username[sizeof(username) - 1] = '\0';

	return username;
}


int main(int argc, char *argv[])
{
	char				pass[MAXPASS + 1];
	int					npass;
	int					force_failure = 0;
	int					retval = PAM_AUTH_ERR;
	char				*user;

	/*
	 * Catch or ignore as many signal as possible.
	 */
	setup_signals();

	/*
	 * we establish that this program is running with non-tty stdin.
	 * this is to discourage casual use. It does *NOT* prevent an
	 * intruder from repeatadly running this program to determine the
	 * password of the current user (brute force attack, but one for
	 * which the attacker must already have gained access to the user's
	 * account).
	 */

	if (isatty(STDIN_FILENO) || argc != 2 )
	{
		_log_err(LOG_NOTICE
		      ,"inappropriate use of Unix helper binary [UID=%d]"
			 ,getuid());
		fprintf(stderr
		 ,"This binary is not designed for running in this way\n"
		      "-- the system administrator has been informed\n");
		sleep(10);	/* this should discourage/annoy the user */
		return PAM_SYSTEM_ERR;
	}
	
	/*
	 * Determine what the current user's name is.
	 * On a SELinux enabled system with a strict policy leaving the
	 * existing check prevents shadow password authentication from working.
	 * We must thus skip the check if the real uid is 0.
	 */
	//if (SELINUX_ENABLED && getuid() == 0)
	if (getuid() == 0)
	{
		user=argv[1];
	}
	else
	{
		user = getuidname(getuid());
		/* if the caller specifies the username, verify that user
	     matches it */
		if (strcmp(user, argv[1]))
		{
			_log_err(LOG_NOTICE
		      ,"mismatch of %s|%s", user, argv[1]);
			return PAM_AUTH_ERR;
		}
	}

	/* read the password from stdin (a pipe from the pam_yubikey module) */
	npass = read(STDIN_FILENO, pass, MAXPASS);

	if (npass < 0)		/* is it a valid password? */
	{
		_log_err(LOG_DEBUG, "no password supplied");
	}
	else if (npass >= MAXPASS)
	{
		_log_err(LOG_DEBUG, "password too long");
	}
	else
	{
		pass[npass] = '\0';	/* NUL terminate */
		retval = _yubi_verify_password(user, pass);
	}

	memset(pass, '\0', MAXPASS);	/* clear memory of the password */

	/* return pass or fail */
	if ((retval != PAM_SUCCESS) || force_failure)
	{
	    _log_err(LOG_NOTICE, "password check failed for user (%s)", user);
	    //return PAM_AUTH_ERR;
	    return retval;
	}
	else
	{
	    return PAM_SUCCESS;
	}
}

int _yubi_verify_password(char *user, char *otp)
{
	int	i;

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

	D (("Recived OTP: %s", otp!=NULL?otp:""));

    /* set additional default values for the entry after parsing */
	getSHA256((uint8_t *)user, strlen(user), (uint8_t *)&entry.user_hash);
	 
    /* perform initial parse to grab public UID */
    parseOTP(&tkt, public_uid_bin, &public_uid_bin_size, (uint8_t *)otp, NULL);
	 
	D (("Parsing OTP"));

    /* OTP needs the public UID for lookup */
    if (public_uid_bin_size <= 0)
	{
		D (("public_uid has no length, OTP is invalid"));
		return PAM_CRED_INSUFFICIENT;
	}

    /* set additional default values for the entry after parsing */
    getSHA256(public_uid_bin, public_uid_bin_size, (uint8_t *)&entry.public_uid_hash);
	 
    /* open the db or create if empty */
    handle = ykdbDatabaseOpen(CONFIG_AUTH_DB_DEFAULT);
    if (handle == NULL)
	{
		D (("couldn't access database: %s", CONFIG_AUTH_DB_DEFAULT));
		return PAM_AUTHINFO_UNAVAIL;
	}
	
    /* seek to public UID if it exists */
    if ( ykdbEntrySeekOnUserHash(handle, (uint8_t *)&entry.user_hash) != YKDB_SUCCESS )
    {
        ykdbDatabaseClose(handle);
		D (("no entry for user: %s", user));
		return PAM_USER_UNKNOWN;
    }

	/* grab the entry */
	if ( ykdbEntryGet(handle, &entry) != YKDB_SUCCESS )
	{
	    ykdbDatabaseClose(handle);

		return PAM_AUTHINFO_UNAVAIL;
	}
	 
	/* start building decryption entry as required */
	safeSnprintf((char *)ticket_enc_key, 256, "TICKET_ENC_KEY_BEGIN");
	 
	/* add hex string format of public uid */
	if ( entry.flags & YKDB_TOKEN_ENC_PUBLIC_UID )
	{
		safeSnprintfAppend((char *)ticket_enc_key, 256, "|", public_uid_bin);
	    for(i=0; i<public_uid_bin_size; i++)
	        safeSnprintfAppend((char *)ticket_enc_key, 256, "%02x", public_uid_bin[i]);
	}
	 
	/* close off decryption key text and generate encryption hash */
	safeSnprintfAppend((char *)ticket_enc_key, 256, "|TICKET_ENC_KEY_END");
	getSHA256(ticket_enc_key, strlen((char *)ticket_enc_key), ticket_enc_hash);
	
    /* decrypt if flags indicate so */
    if ( entry.flags & YKDB_TOKEN_ENC_PUBLIC_UID ||
         entry.flags & YKDB_TOKEN_ENC_PASSWORD )
    {
        aesDecryptCBC((uint8_t *)&entry.ticket, sizeof(ykdb_entry_ticket), ticket_enc_key, ticket_enc_key+16);
    }
 
    /* perform real parse to grab real ticket, using the now unecrypted key */
    parseOTP(&tkt, public_uid_bin, &public_uid_bin_size, (uint8_t *)otp, (uint8_t *)&entry.ticket.key);
 
    /* check CRC matches */
    crc = getCRC((uint8_t *)&tkt, sizeof(yk_ticket));
    ENDIAN_SWAP_16(crc);
 
	/* no use continuing if the decoded OTP failed */
    if ( crc != CRC_OK_RESIDUE )
    {
        ykdbDatabaseClose(handle);
		D (("crc invalid: 0x%04x", crc));

		return PAM_AUTH_ERR;
    }

    /* hash decrypted private uid */
    getSHA256(tkt.private_uid, PRIVATE_UID_BYTE_SIZE, (uint8_t *)&tkt_private_uid_hash);
 
    /* match private uid hashes */
    if ( memcmp(&tkt_private_uid_hash, &entry.ticket.private_uid_hash, 32) )
    {
        ykdbDatabaseClose(handle);
		D (("private uid mismatch"));
		return PAM_AUTH_ERR;
    }

	/* check counter deltas */
	delta_use = tkt.use_counter - entry.ticket.last_use;
	delta_session = tkt.session_counter - entry.ticket.last_session;

	if ( delta_use < 0 )
	{
		ykdbDatabaseClose(handle);
		D (("OTP is INVALID. Possible replay!!!"));
		return PAM_AUTH_ERR;
	}
	
	if ( delta_use == 0 && delta_session <= 0 )
	{
		ykdbDatabaseClose(handle);
		D (("OTP is INVALID. Possible replay!!!"));
		return PAM_AUTH_ERR;
	}
	
	/* update the database entry with the latest counters */
	entry.ticket.last_use = tkt.use_counter;
	entry.ticket.last_timestamp_lo = tkt.timestamp_lo;
	entry.ticket.last_timestamp_hi = tkt.timestamp_hi;
	entry.ticket.last_session = tkt.session_counter;

	/* re-encrypt and write to database */
	if ( entry.flags & YKDB_TOKEN_ENC_PUBLIC_UID ||
		 entry.flags & YKDB_TOKEN_ENC_PASSWORD )
	{
		aesEncryptCBC((uint8_t *)&entry.ticket, sizeof(ykdb_entry_ticket), ticket_enc_key, ticket_enc_key+16);
	}

	/* re-encrypt and write to database */
	if ( ykdbEntryWrite(handle, &entry) != YKDB_SUCCESS )
	{
		ykdbDatabaseClose(handle);
		return PAM_AUTHINFO_UNAVAIL;
	}

	return PAM_SUCCESS;
}

