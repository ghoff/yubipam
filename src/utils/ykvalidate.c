/*
* YubiKey PAM Validate Module
*
* Copyright (C) 2008 Ian Firns		firnsy@securixlive.com
* Copyright (C) 2008 SecurixLive	dev@securixlive.com
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

#include <getopt.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ykvalidate.h"
#include "libyubipam.h"

int						amroot;
char					*user_text = NULL;
char					*progname;

void cleanExit(int mode);
char * getInput(const char *prompt, int size, int required);
struct passwd *getPWEnt(void);
void showUsage(char *);

int main(int argc, char *argv[])
{
	int i;
	
	uint8_t				ticket_enc_key[256];
	uint8_t				ticket_enc_hash[32];

	char				*password_text = NULL;

	uint8_t				public_uid_text[PUBLIC_UID_BYTE_SIZE<<1];
	uint8_t				public_uid_bin[PUBLIC_UID_BYTE_SIZE];
	uint8_t				public_uid_bin_size = 0;

	yk_ticket			tkt;
	ykdb_entry			entry;
	ykdb_h				*handle;

	uint8_t				tkt_private_uid_hash[32];

	uint32_t			crc;

	int					delta_use;
	int					delta_session;

    struct passwd       *pw;


	progname = argv[0];

	/* expect only the OTP as an argument */
	if (argc != 3)
	{
		showUsage(progname);
		return 1;
	}

	user_text = strdup(argv[1]);

	amroot = ( getuid() == 0 );

    /* get passwd structure for current user */
    pw = getPWEnt();
 
    if (!pw)
    {
        fprintf(stderr, "Can't determine your user name\n");
        cleanExit(1);
    }
 
    if (user_text == NULL)
    {
        user_text = strdup(pw->pw_name);
    }

    /* get passwd structure for desired user */
	pw = getpwnam(user_text);
	 
	if (!pw)
	{
	    fprintf(stderr, "Unknown user: %s\n", user_text);
	    cleanExit(1);
	}
	 
	/* check if we have privelege to update users information */
	if ( !amroot && pw->pw_uid != getuid() )
	{
		fprintf(stderr, "You may not view or modify yubikey information for %s\n", user_text);
		cleanExit(1);
	}
	
	/* Get perms */
	setregid( getegid(), -1 );

    /* set additional default values for the entry after parsing */
    getSHA256(user_text, strlen(user_text), (uint8_t *)&entry.user_hash);

	/* perform initial parse to grab public UID */
	parseOTP(&tkt, public_uid_bin, &public_uid_bin_size, argv[2], NULL);

	/* OTP needs the public UID for lookup */
	if (public_uid_bin_size <= 0)
		cleanExit(1);

	/* set additional default values for the entry after parsing */
	getSHA256(public_uid_bin, public_uid_bin_size, (uint8_t *)&entry.public_uid_hash);

	/* open the db or create if empty */
	handle = ykdbDatabaseOpen(CONFIG_AUTH_DB_DEFAULT);
	if (handle == NULL)
		cleanExit(1);

	/* seek to public UID if it exists */
	if ( ykdbEntrySeekOnUserHash(handle, (uint8_t *)&entry.user_hash) != YKDB_SUCCESS )
	{
		ykdbDatabaseClose(handle);
		cleanExit(1);
	}

	/* grab the found entry */
	if ( ykdbEntryGet(handle, &entry) != YKDB_SUCCESS )
	{
		ykdbDatabaseClose(handle);
		cleanExit(1);
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
	if ( entry.flags & YKDB_TOKEN_ENC_PASSWORD )
	{
		/* obtain and store the second factor passcode if not already defined */
		password_text = getInput("Password: ", 256, 0);
		
		if (password_text != NULL)
		{
			getSHA256(password_text, strlen(password_text), (uint8_t *)&entry.password_hash);
			safeSnprintfAppend(ticket_enc_key, 256, "|%s", password_text);

			free(password_text);
		}
	}

	/* close off decryption key text and generate encryption hash */
	safeSnprintfAppend(ticket_enc_key, 256, "|TICKET_ENC_KEY_END");
	getSHA256(ticket_enc_key, strlen(ticket_enc_key), ticket_enc_hash);

#ifdef DEBUG
	printf("Using key: %s\n", ticket_enc_key);
#endif

	/* decrypt if flags indicate so */
	if ( entry.flags & YKDB_TOKEN_ENC_PUBLIC_UID ||
		 entry.flags & YKDB_TOKEN_ENC_PASSWORD )
	{
		aesDecryptCBC((uint8_t *)&entry.ticket, sizeof(ykdb_entry_ticket), ticket_enc_key, ticket_enc_key+16);
	}

	/* perform real parse to grab real ticket */
	parseOTP(&tkt, public_uid_bin, &public_uid_bin_size, argv[2], (uint8_t *)&entry.ticket.key);

#ifdef DEBUG
	printf("Decrypted database entry\n");
	ykdbPrintEntry(&entry);
	printf("\n");
	printf("Decrypted Yubikey ticket\n");
	printTicket(&tkt);
#endif

	/* check CRC matches */
	crc = getCRC((uint8_t *)&tkt, sizeof(yk_ticket));
	ENDIAN_SWAP_16(crc);
		
#ifdef DEBUG
	printf("Ticket CRC: 0x%04x (expect: 0x%04x)\n", crc, CRC_OK_RESIDUE);
#endif

	/* no use continuing if the decoded OTP failed */
	if ( crc != CRC_OK_RESIDUE )
	{
		ykdbDatabaseClose(handle);
		cleanExit(1);
	}

	/* hash decrypted private uid */
	getSHA256(tkt.private_uid, PRIVATE_UID_BYTE_SIZE, (uint8_t *)&tkt_private_uid_hash);

	/* match private uid hashes */
	if ( memcmp(&tkt_private_uid_hash, &entry.ticket.private_uid_hash, 32) )
	{
		ykdbDatabaseClose(handle);
		cleanExit(1);
	}

#ifdef DEBUG
	printf("Private UID's MATCH!!!\n");
#endif

	/* check counter deltas */
	delta_use = tkt.use_counter - entry.ticket.last_use;
	delta_session = tkt.session_counter - entry.ticket.last_session;

	if ( delta_use < 0 )
	{
		printf("OTP is INVALID. Possible replay!!!\n");
		ykdbDatabaseClose(handle);
		cleanExit(1);
	}
	
	if ( delta_use == 0 && delta_session <= 0 )
	{
		printf("OTP is INVALID. Possible replay!!!\n");
		ykdbDatabaseClose(handle);
		cleanExit(1);
	}
	
#ifdef DEBUG
	printf("Delta's OK!!\n");
#endif

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
		cleanExit(1);
	}

	printf("OTP is VALID.\n");

	/* close the db */
	ykdbDatabaseClose(handle);

	cleanExit(0);
}

void showUsage(char *program_name)
{
    fprintf(stdout, "USAGE: %s USER OTP\n", program_name);
	fprintf(stdout, "\n");
}

void cleanExit(int mode)
{
	if (user_text);
		free(user_text);

	exit(mode);
}

/*
** showUsage
**
** Description:
**   Show program version.
*/
int showVersion(void)
{
    fprintf(stderr, "\n"
   					"ykvalidate - Yubikey OTP Validation Utility\n"
			        "Version %s.%s.%s (Build %s)\n"
			        "By the SXL.com team: http://www.securixlive.com/contact.html\n"
					"\n", VER_MAJOR, VER_MINOR, VER_REVISION, VER_BUILD); 

	return 0;
}

static char *valid_options = "?adcf:k:p:F:P:sV";
/* courtesy myname.c (pam_unix) */
struct passwd *getPWEnt(void)
{
    struct passwd       *pw;
    const char          *cp = getlogin();
    uid_t               ruid = getuid();

    if (cp && *cp && (pw = getpwnam(cp)) && pw->pw_uid == ruid)
        return pw;
 
	return getpwuid(ruid);
}

char * getInput(const char *prompt, int size, int required)
{
	int bytes_read;
	int gl_size = 0;
	char *answer;

	while ( (bytes_read-1) != required )
	{
		printf("%s", prompt);
		answer = malloc(size + 1);
		bytes_read = getline(&answer, &gl_size, stdin);

		if (required <= 0)
			break;

		if (answer == NULL)
			return NULL;
	}

	if (bytes_read >= size)
		answer[size] = '\0';
	else
		answer[bytes_read-1] = '\0';

	return answer;
}

