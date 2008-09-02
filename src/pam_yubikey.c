/*
* YubiKey PAM Module
*
* Copyright (C) 2008 Ian Firns firnsy@securixlive.com
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

	int nargs = 1;
	int debug = 0;
	int silent_otp = 0;

	for (i = 0; i < argc; i++)
	{
	    if (strncmp(argv[i], "debug", 5) == 0)
			debug = 1;
		else if (strncmp(argv[i], "silent", 6) == 0)
			silent_otp = 1;
	}

#ifdef DEBUG
	if (debug)
	{
		D (("called."));
		D (("flags %d argc %d", flags, argc));
		for (i = 0; i < argc; i++)
			D (("argv[%d]=%s", i, argv[i]));
		D (("debug=%d", debug));
		D (("silent=%d", silent_otp));
    }
#endif

	/* obtain the user requesting authentication */
	retval = pam_get_user (pamh, &user, NULL);
	if (retval != PAM_SUCCESS)
    {
#ifdef DEBUG
		if (debug)
			D (("get user returned error: %s", pam_strerror (pamh, retval)));
#endif
		goto done;
    }
	
#ifdef DEBUG
	if (debug)
		D (("get user returned: %s", user));
#endif
	
	/* obtain existing authenticated token */
	retval = pam_get_item (pamh, PAM_AUTHTOK, (const void **) &otp);
	if (retval != PAM_SUCCESS)
    {
#ifdef DEBUG
		if (debug)
			D (("get otp returned error: %s", pam_strerror (pamh, retval)));
#endif
		goto done;
    }

#ifdef DEBUG
	if (debug)
		D (("get otp returned: %s", otp));
#endif

	if (otp == NULL)
	{
		retval = pam_get_item (pamh, PAM_CONV, (const void **) &conv);
		if (retval != PAM_SUCCESS)
		{
#ifdef DEBUG
			if (debug)
				D (("get conv returned error: %s", pam_strerror (pamh, retval)));
#endif
			goto done;
		}

		pmsg[0] = &msg[0];
		asprintf ((char **) &msg[0].msg, "Yubikey OTP for '%s': ", user);
		
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
			if (debug)
				D (("conv returned error: %s", pam_strerror (pamh, retval)));
#endif
			goto done;
		}

#ifdef DEBUG
		if (debug)
			D (("conv returned: %s", resp->resp));
#endif

		otp = resp->resp;

		retval = pam_set_item(pamh, PAM_AUTHTOK, otp);
      
		if (retval != PAM_SUCCESS)
		{
#ifdef DEBUG
			if (debug)
				D (("set_item returned error: %s", pam_strerror (pamh, retval)));
#endif
			goto done;
		}
    }

    /* set additional default values for the entry after parsing */
	getSHA256(user, strlen(user), (uint8_t *)&entry.user_hash);
	 
    /* perform initial parse to grab public UID */
    parseOTP(&tkt, public_uid_bin, &public_uid_bin_size, otp, NULL);
	 
#ifdef DEBUG
	if (debug)
		D (("Parsing OTP"));
#endif

    /* OTP needs the public UID for lookup */
    if (public_uid_bin_size <= 0)
	{
#ifdef DEBUG
		if (debug)
			D (("public_uid has no length, OTP is invalid"));
#endif

		retval = PAM_CRED_INSUFFICIENT;
		goto done;
	}

    /* set additional default values for the entry after parsing */
    getSHA256(public_uid_bin, public_uid_bin_size, (uint8_t *)&entry.public_uid_hash);
	 
    /* open the db or create if empty */
    handle = ykdbDatabaseOpen(CONFIG_AUTH_DB_DEFAULT);
    if (handle == NULL)
	{
#ifdef DEBUG
		if (debug)
			D (("couldn't access database: %s", CONFIG_AUTH_DB_DEFAULT));
#endif

		retval = PAM_AUTHINFO_UNAVAIL;
		goto done;
	}
	
    /* seek to public UID if it exists */
    if ( ykdbEntrySeekOnUserHash(handle, (uint8_t *)&entry.user_hash) != YKDB_SUCCESS )
    {
        ykdbDatabaseClose(handle);
#ifdef DEBUG
		if (debug)
			D (("no entry for user: %s", user));
#endif

		retval = PAM_USER_UNKNOWN;
		goto done;
    }

	/* grab the found entry */
	if ( ykdbEntryGet(handle, &entry) != YKDB_SUCCESS )
	{
	    ykdbDatabaseClose(handle);

		retval = PAM_AUTHINFO_UNAVAIL;
		goto done;
	}
	 
	/* start building decryption entry as required */
	safeSnprintf(ticket_enc_key, 256, "TICKET_ENC_KEY_BEGIN");
	 
	/* add hex string format of public uid */
	if ( entry.flags & YKDB_TOKEN_ENC_PUBLIC_UID )
	{
		safeSnprintfAppend(ticket_enc_key, 256, "|", public_uid_bin);
	    for(i=0; i<public_uid_bin_size; i++)
	        safeSnprintfAppend(ticket_enc_key, 256, "%02x", public_uid_bin[i]);
	}
	 
	/* add additional password if required */
//	if ( entry.flags & YKDB_TOKEN_ENC_PASSWORD )
//	{
//	    /* obtain and store the second factor passcode if not already defined */
//	    password_text = getInput("Password: ", 256, 0);
//	 
//	    if (password_text != NULL)
//	    {
//	        getSHA256(password_text, strlen(password_text), (uint8_t *)&entry.password_hash);
//	        safeSnprintfAppend(ticket_enc_key, 256, "|%s", password_text);
//	        free(password_text);
//	    }
//	}
	 
	/* close off decryption key text and generate encryption hash */
	safeSnprintfAppend(ticket_enc_key, 256, "|TICKET_ENC_KEY_END");
	getSHA256(ticket_enc_key, strlen(ticket_enc_key), ticket_enc_hash);
	
    /* decrypt if flags indicate so */
    if ( entry.flags & YKDB_TOKEN_ENC_PUBLIC_UID ||
         entry.flags & YKDB_TOKEN_ENC_PASSWORD )
    {
        aesDecryptCBC((uint8_t *)&entry.ticket, sizeof(ykdb_entry_ticket), ticket_enc_key, ticket_enc_key+16);
    }
 
    /* perform real parse to grab real ticket, using the now unecrypted key */
    parseOTP(&tkt, public_uid_bin, &public_uid_bin_size, otp, (uint8_t *)&entry.ticket.key);
 
    /* check CRC matches */
    crc = getCRC((uint8_t *)&tkt, sizeof(yk_ticket));
    ENDIAN_SWAP_16(crc);
 
	/* no use continuing if the decoded OTP failed */
    if ( crc != CRC_OK_RESIDUE )
    {
        ykdbDatabaseClose(handle);
#ifdef DEBUG
		if (debug)
			D (("crc invalid: 0x%04x", crc));
#endif

		retval = PAM_AUTH_ERR;
		goto done;
    }

    /* hash decrypted private uid */
    getSHA256(tkt.private_uid, PRIVATE_UID_BYTE_SIZE, (uint8_t *)&tkt_private_uid_hash);
 
    /* match private uid hashes */
    if ( memcmp(&tkt_private_uid_hash, &entry.ticket.private_uid_hash, 32) )
    {
        ykdbDatabaseClose(handle);
#ifdef DEBUG
		if (debug)
			D (("private uid mismatch"));
#endif

		retval = PAM_AUTH_ERR;
		goto done;
    }

	/* check counter deltas */
	delta_use = tkt.use_counter - entry.ticket.last_use;
	delta_session = tkt.session_counter - entry.ticket.last_session;

	if ( delta_use < 0 )
	{
		ykdbDatabaseClose(handle);
#ifdef DEBUG
		if (debug)
			D (("OTP is INVALID. Possible replay!!!"));
#endif

		retval = PAM_AUTH_ERR;
		goto done;
	}
	
	if ( delta_use == 0 && delta_session <= 0 )
	{
		ykdbDatabaseClose(handle);
#ifdef DEBUG
		if (debug)
			D (("OTP is INVALID. Possible replay!!!"));
#endif

		retval = PAM_AUTH_ERR;
		goto done;
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
		retval = PAM_AUTHINFO_UNAVAIL;
		goto done;
	}

	retval = PAM_SUCCESS;

done:
	pam_set_data (pamh, "yubikey_setcred_return", (void *) retval, NULL);

#ifdef DEBUG
	if (debug)
		D (("done. [%s]", pam_strerror (pamh, retval)));
#endif

	return retval;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
	int retval;
	int auth_retval;

	D (("called."));

  /* TODO: ? */

  retval = pam_get_data (pamh, "yubikey_setcred_return",
			 (const void **) &auth_retval);

  if (retval != PAM_SUCCESS)
    return PAM_CRED_UNAVAIL;

  switch (auth_retval)
    {
    case PAM_SUCCESS:
      retval = PAM_SUCCESS;
      break;

    case PAM_USER_UNKNOWN:
      retval = PAM_USER_UNKNOWN;
      break;

    case PAM_AUTH_ERR:
    default:
      retval = PAM_CRED_ERR;
      break;
    }

  D (("done. [%s]", pam_strerror (pamh, retval)));

  return retval;
}

PAM_EXTERN int
pam_sm_acct_mgmt (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
  int retval;

  D (("called."));

  /* TODO: ? */
  retval = PAM_SUCCESS;

  D (("done. [%s]", pam_strerror (pamh, retval)));

  return retval;
}

PAM_EXTERN int
pam_sm_open_session (pam_handle_t * pamh,
		     int flags, int argc, const char **argv)
{
  int retval;

  D (("called."));

  /* TODO: ? */
  retval = PAM_SUCCESS;

  D (("done. [%s]", pam_strerror (pamh, retval)));

  return retval;
}

PAM_EXTERN int
pam_sm_close_session (pam_handle_t * pamh,
		      int flags, int argc, const char **argv)
{
  int retval;

  D (("called."));

  /* TODO: ? */
  retval = PAM_SUCCESS;

  D (("done. [%s]", pam_strerror (pamh, retval)));

  return retval;
}

PAM_EXTERN int
pam_sm_chauthtok (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
  int retval;

  D (("called."));

  /* TODO: ? */
  retval = PAM_SUCCESS;

  D (("done. [%s]", pam_strerror (pamh, retval)));

  return retval;
}

#ifdef PAM_STATIC

struct pam_module _pam_yubikey_modstruct = {
  "pam_yubikey",
  pam_sm_authenticate,
  pam_sm_setcred,
  pam_sm_acct_mgmt,
  pam_sm_open_session,
  pam_sm_close_session,
  pam_sm_chauthtok
};

#endif
