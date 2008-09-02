/*
* YubiKey PAM Passwd Module
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

#include "libyubipam.h"
#include "ykpasswd.h"


char					*progname;

int						amroot;

char					*otp;
char					*user_text;
char					*public_uid_text = NULL;
uint8_t					public_uid_bin[PUBLIC_UID_BYTE_SIZE];
uint8_t					public_uid_bin_size = 0;
char					*key_text = NULL;
uint8_t					key_bin[KEY_BYTE_SIZE];
char					*private_uid_text = NULL;
uint8_t					private_uid_bin[PRIVATE_UID_BYTE_SIZE];
uint8_t					private_uid_bin_size = 0;
char					*password_text = NULL;

int						mode;
ykdb_entry				entry;
ykdb_h					*handle;
yk_ticket				tkt;

extern					ykdb_errno;

char *getInput(const char *prompt, int size, int required);
struct passwd *getPWEnt(void);
int showUsage(char *progam_name);
int showVersion(void);

void cleanExit(int mode);

int main (int argc, char *argv[])
{
	uint8_t				user_exists = 0;
	struct passwd		*pw;
	int					retval;
	

	/* save the program name */
	progname = argv[0];

	/* set default values for the entry */
	entry.flags = YKDB_TOKEN_ENC_PUBLIC_UID;
	entry.ticket.last_use = 0x0000;
	entry.ticket.last_timestamp_lo = 0x0000;
	entry.ticket.last_timestamp_hi = 0x00;
	entry.ticket.last_session = 0x00;
	
	parseCommandLine(argc, argv);

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

	/* show usage when in USAGE mode or no user was provided */
	if (mode == MODE_USAGE || user_text == NULL)
	{
		showUsage(progname);
		cleanExit(1);
	}
	else if (mode == MODE_VERSION)
	{
		showVersion();
	}

	/* set additional default values for the entry after parsing */
	getSHA256(user_text, strlen(user_text), (uint8_t *)&entry.user_hash);


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
//	printf("EGID: %d\n", getegid());
    setregid( getegid(), -1 );

	/* open the db or create if empty */
	handle = ykdbDatabaseOpen(CONFIG_AUTH_DB_DEFAULT);
	if (handle == NULL)
	{
		handle = ykdbDatabaseCreate(CONFIG_AUTH_DB_DEFAULT);

		if (handle == NULL)
		{
			printf("Unable to access the database: %s [%d]\n", CONFIG_AUTH_DB_DEFAULT, ykdb_errno);
			cleanExit(1);
		}
	}

	/* seek to user entry if it exists */
	if ( ykdbEntrySeekOnUserHash(handle, (uint8_t *)&entry.user_hash) == YKDB_SUCCESS )
		user_exists = 1;

	if (mode == MODE_ADD)
	{
		/* can't add when one already exists */
		if (user_exists)
		{
			fprintf(stderr, "Entry for %s already exist.\n", user_text);
			cleanExit(1);
		}

		if ( addYubikeyEntry() != 0 )
			cleanExit(1);
	}
	else if (mode == MODE_UPDATE)
	{
		/* can't update when one doesn't exist */
		if (!user_exists)
		{
			fprintf(stderr, "Entry for %s does not exist.\n", user_text);
			cleanExit(1);
		}

		if ( updateYubikeyEntry() != 0)
			cleanExit(1);
	}
	else if (mode == MODE_DELETE)
	{
		/* can't delete when one doesn't exist */
		if (!user_exists)
		{
			fprintf(stderr, "Entry for %s does not exist.\n", user_text);
			cleanExit(1);
		}

		if ( deleteYubikeyEntry() != 0 )
			cleanExit(1);
	}

	/* sync to the yubikey */



	/* close the db */
	ykdbDatabaseClose(handle);

	cleanExit(0);
}

/*
** cleanExit
**
** Description:
**   Cleans up any memory that was allocated prior to exit.
**
** Arguments:
**   int mode					exit number
*/
void cleanExit(int mode)
{
	/* free any and all allocated memory */
	if (otp)
		free(otp);

	if (user_text)
		free(user_text);

	if (public_uid_text)
		free(public_uid_text);

	if (private_uid_text)
		free(private_uid_text);

	if (password_text)
		free(password_text);

	/* exit as required */
	exit(mode);
}



/*
** showUsage
**
** Description:
**   Show program usage.
**
** Arguments:
**   char *program_name			program name
*/
int showUsage(char *program_name)
{
    fprintf(stdout, "USAGE: %s [-options] USER\n", program_name);
	fprintf(stdout, "\n");
	fprintf(stdout, "Options:\n");
	fprintf(stdout, "   -?          Show this information\n");
    fprintf(stdout, "   -a          Add yubikey to database\n");
    fprintf(stdout, "   -d          Delete yubikey from database\n");
//    fprintf(stdout, "   -c          Prompt for second factor pass code\n");
    fprintf(stdout, "   -f <uid>    Public uid in hex\n");
    fprintf(stdout, "   -k <key>    AES key in hex\n");
    fprintf(stdout, "   -o <otp>    Yubikey generated OTP\n");
    fprintf(stdout, "   -p <uid>    Private uid in hex\n");
    fprintf(stdout, "   -u <user>   Alternative method for indicating user\n");
//    fprintf(stdout, "   -s          Sync to yubikey dongle\n");
    fprintf(stdout, "   -V          Show version and exit\n");
	fprintf(stdout, "\n");
//	fprintf(stdout, "Update options:\n");
//    fprintf(stdout, "   -F <uid>    Force new public uid in hex\n");
//    fprintf(stdout, "   -P <uid>    Force new private uid in hex\n");
//	fprintf(stdout, "\n");
    fprintf(stdout, "Longname options and their corresponding single char version\n");
//    fprintf(stdout, "   --tab1          Prepend a tab character to the public uid\n");
//    fprintf(stdout, "   --tab2          Append a tab character to the public uid\n");
//    fprintf(stdout, "   --tab3          Append a tab character to the encrypted ticket\n");
//    fprintf(stdout, "   --delay10       Add 10ms intra-key spacing\n");
//    fprintf(stdout, "   --delay20       Add 20ms intra-key spacing\n");
//    fprintf(stdout, "   --cr            Append a carriage return as the final character\n");
//    fprintf(stdout, "   --sendref       Send reference string (0..f) before any data\n");
//    fprintf(stdout, "   --ticketfirst   Send encrypted ticket before public uid\n");
    fprintf(stdout, "   --help          Same as -?\n");
    fprintf(stdout, "   --version       Same as -V\n");
	fprintf(stdout, "\n");
	 
	return 0;
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
   					"ykpasswd - Yubikey Password Utility\n"
			        "Version %s.%s.%s (Build %s)\n"
			        "By the SXL.com team: http://www.securixlive.com/contact.html\n"
					"\n", VER_MAJOR, VER_MINOR, VER_REVISION, VER_BUILD); 

	return 0;
}

static char *valid_options = "?adcf:k:o:p:u:F:P:sV";

#define LONGOPT_ARG_NONE 0
#define LONGOPT_ARG_REQUIRED 1
#define LONGOPT_ARG_OPTIONAL 2
static struct option long_options[] = {
   {"help", LONGOPT_ARG_NONE, NULL, '?'},
   {"tab1", LONGOPT_ARG_NONE, NULL, TF_TAB_1},
   {"tab2", LONGOPT_ARG_NONE, NULL, TF_TAB_2},
   {"tab3", LONGOPT_ARG_NONE, NULL, TF_TAB_3},
   {"delay1", LONGOPT_ARG_NONE, NULL, TF_DELAY_1},
   {"delay2", LONGOPT_ARG_NONE, NULL, TF_DELAY_2},
   {"cr", LONGOPT_ARG_NONE, NULL, TF_CR},
   {"sendref", LONGOPT_ARG_NONE, NULL, CF_SEND_REF},
   {"ticketfirst", LONGOPT_ARG_NONE, NULL, CF_TICKET_FIRST},
   {"pacing10", LONGOPT_ARG_NONE, NULL, CF_PACING_10},
   {"pacing20", LONGOPT_ARG_NONE, NULL, CF_PACING_20},
   {"static", LONGOPT_ARG_NONE, NULL, CF_STATIC},
   {"version", LONGOPT_ARG_NONE, NULL, 'V'},
   {"help", LONGOPT_ARG_NONE, NULL, '?'},
   {0, 0, 0, 0}
};

int parseCommandLine(int argc, char *argv[])
{
    int ch;                         /* storage var for getopt info */
    int option_index = -1;
    int isName = 0;
    int i;

    /* just to be sane.. */
    mode = MODE_UPDATE;

    /*
    **  Set this so we know whether to return 1 on invalid input because we
    **  use '?' for help and getopt uses '?' for telling us there was an
	**  invalid option, so we can't use that to tell invalid input. Instead,
	**  we check optopt and it will tell us.
    */
    optopt = 0;

    /* loop through each command line var and process it */
    while((ch = getopt_long(argc, argv, valid_options, long_options, &option_index)) != -1)
    {
        switch(ch)
        {
            case CF_STATIC:
                break;
            
            case '?': /* show help and exit with 1 */
				mode = MODE_USAGE;
				break;

            case 'V': /* show version information */
				mode = MODE_VERSION;
				break;

			case 'a': /* add yubikey entry to the database */
				mode = MODE_ADD;
				break;

			case 'c': /* prompt for additional password (2nd factor */
				entry.flags |= YKDB_TOKEN_ENC_PASSWORD;
				break;

			case 'd': /* delete yubikey entry to the database */
				mode = MODE_DELETE;
				break;
			
			case 'k': /* AES key */
				key_text = strdup(optarg);
				break;

			case 'f': /* Public UID */
				public_uid_text = strdup(optarg);
				break;

			case 'o': /* Yubikey OTP */
				otp = strdup(optarg);
				break;

			case 'p': /* Private UID */
				private_uid_text = strdup(optarg);
				break;

			case 'u': /* Private UID */
				user_text = strdup(optarg);
				break;
		}	
	}
	
	/* there should be at least one left over argument */
	if (optind < argc && user_text != NULL)
	{
		/* grab the first additional argument as the user name */
		user_text = strdup(argv[optind]);
	}
}

int addYubikeyEntry(void)
{
	uint8_t				ticket_enc_key[256];
	uint8_t				ticket_enc_hash[32];
	uint8_t				i;

	printf("Adding Yubikey entry for %s\n", user_text);
	
	/* obtain and store the AES key if not already defined */
	if (key_text == NULL)
		key_text = getInput("AES key [exactly 32 hex chars]: ", 32, 32);
	
	if (key_text != NULL)
	{
		if ( !checkHexString(key_text) )
			hexDecode((uint8_t *)&entry.ticket.key, key_text, KEY_BYTE_SIZE);
		else if ( !checkModHexString(key_text) )
			modHexDecode((uint8_t *)&entry.ticket.key, key_text, KEY_BYTE_SIZE);
		else
		{
			printf("Invalid key specified!\n");
			return -1;
		}
	}
	else
	{
		printf("No key specified!\n");
		return -1;
	}

	/* check for an OTP first which will provide public UID and private UID */
	/* with a valid key */
	if (otp != NULL)
	{
		/* decode the OTP */
		if ( parseOTP(&tkt, public_uid_bin, &public_uid_bin_size, otp, entry.ticket.key ) != 0 )
		{
			printf("Invalid OTP specified!\n");
			return -1;
		}

		/* print public UID */
		if (public_uid_bin_size > 0)
		{
			printf("Using public UID: ");
			for (i=0; i<public_uid_bin_size; i++)
				printf("%02x ", public_uid_bin[i]);
			printf("\n");
		}

		/* extract the private UID */
		memcpy(private_uid_bin, tkt.private_uid, PRIVATE_UID_BYTE_SIZE);

		/* print private UID */
		private_uid_bin_size = PRIVATE_UID_BYTE_SIZE;
		printf("Using private UID: ");
		for (i=0; i<PRIVATE_UID_BYTE_SIZE; i++)
			printf("%02x ", tkt.private_uid[i]);
		printf("\n");

		/* extract counter information, because we can */
		entry.ticket.last_use = tkt.use_counter;
		entry.ticket.last_timestamp_lo = tkt.timestamp_lo;
		entry.ticket.last_timestamp_hi = tkt.timestamp_hi;
		entry.ticket.last_session = tkt.session_counter;
	}

	/* obtain the private_uid if not already defined and store the hash */
	if (public_uid_text == NULL && public_uid_bin_size <= 0)
		public_uid_text = getInput("Public UID [max 32 hex chars]: ", 32, 0);

	if (public_uid_text != NULL && public_uid_bin_size <= 0)
	{
		/* decode the public uid if in hex format */
		if ( !checkHexString(public_uid_text) )
		{
			if ( strlen(public_uid_text) > 32 )
			{
				printf("Public UID is too long! Max of 32 hex chars allowed.\n");
				return -1;
			}
			public_uid_bin_size = hexDecode(public_uid_bin, public_uid_text, PUBLIC_UID_BYTE_SIZE);
		}
		/* decode the public uid if in modhex format */
		else if ( !checkModHexString(public_uid_text) )
		{
			if ( strlen(public_uid_text) > 32 )
			{
				printf("Public UID is too long! Max of 32 modhex chars allowed.\n");
				return -1;
			}
			public_uid_bin_size = modHexDecode(public_uid_bin, public_uid_text, PUBLIC_UID_BYTE_SIZE);
		}
		else
		{
			printf("Public UID [%s] must be in hex format!\n", public_uid_text);
			return -1;
		}
	}
	else if (public_uid_bin_size <= 0)
	{
		printf("No Public UID specified!\n");
		return -1;
	}

	getSHA256(public_uid_bin, public_uid_bin_size, (uint8_t *)&entry.public_uid_hash);

	/* obtain the private_uid if not already defined and store the hash */
	if (private_uid_text == NULL && private_uid_bin_size <= 0)
		private_uid_text = getInput("Private UID [exactly 12 hex chars]: ", 12, 12);

	if (private_uid_text != NULL && private_uid_bin_size <= 0)
	{
		if ( !checkHexString(private_uid_text) )
			hexDecode(private_uid_bin, private_uid_text, PRIVATE_UID_BYTE_SIZE);
		else if ( !checkModHexString(private_uid_text) )
			modHexDecode(private_uid_bin, private_uid_text, PRIVATE_UID_BYTE_SIZE);
		else
		{
			printf("Invalid UID specified!\n");
			return -1;
		}
	}
	else if ( private_uid_bin_size <= 0)
	{
		printf("No Private UID specified!\n");
		return -1;
	}

	getSHA256(private_uid_bin, PRIVATE_UID_BYTE_SIZE, (uint8_t *)&entry.ticket.private_uid_hash);

	/* encrypt entry as required */
	safeSnprintf(ticket_enc_key, 256, "TICKET_ENC_KEY_BEGIN");

	if ( entry.flags & YKDB_TOKEN_ENC_PUBLIC_UID )
	{
		safeSnprintfAppend(ticket_enc_key, 256, "|", public_uid_bin);
		for(i=0; i<public_uid_bin_size; i++)
			safeSnprintfAppend(ticket_enc_key, 256, "%02x", public_uid_bin[i]);
	}
	
	if ( entry.flags & YKDB_TOKEN_ENC_PASSWORD )
	{
		/* obtain and store the second factor passcode if not already defined */
		password_text = getInput("Password: ", 256, 0);
		
		if (password_text != NULL)
		{
			getSHA256(password_text, strlen(password_text), (uint8_t *)&entry.password_hash);
			safeSnprintfAppend(ticket_enc_key, 256, "|%s", password_text);
		}
	}
	
	safeSnprintfAppend(ticket_enc_key, 256, "|TICKET_ENC_KEY_END");

#ifdef DEBUG
	printf("Using encryption key: %s\n", ticket_enc_key);
#endif

	if ( entry.flags & YKDB_TOKEN_ENC_PUBLIC_UID ||
		 entry.flags & YKDB_TOKEN_ENC_PASSWORD )
	{
		getSHA256(ticket_enc_key, strlen(ticket_enc_key), ticket_enc_hash);
		aesEncryptCBC((uint8_t *)&entry.ticket, sizeof(ykdb_entry_ticket), ticket_enc_key, ticket_enc_key+16);
	}

	if ( ykdbEntryAdd(handle, &entry) != YKDB_SUCCESS )
	{
		printf("Unable to write to the database: %s [%d]\n", YKDB_FILE, ykdb_errno);
		return 1;
	}

#ifdef DEBUG
	/* print the entry */
	ykdbPrintEntry(&entry);
#endif

	return 0;
}

int updateYubikeyEntry(void)
{
	uint8_t				ticket_enc_key[256];
	uint8_t				ticket_enc_hash[32];
	uint8_t				i;

	ykdb_entry			tmp_entry;

	printf("Updating Yubikey entry for %s\n", user_text);

	if ( ykdbEntryGet(handle, &tmp_entry) != YKDB_SUCCESS )
		return 1;

	/* decrypt entry before updating */
	safeSnprintf(ticket_enc_key, 256, "TICKET_ENC_KEY_BEGIN");

	if ( tmp_entry.flags & YKDB_TOKEN_ENC_PUBLIC_UID )
	{
		safeSnprintfAppend(ticket_enc_key, 256, "|", public_uid_bin);
		for(i=0; i<public_uid_bin_size; i++)
			safeSnprintfAppend(ticket_enc_key, 256, "%02x", public_uid_bin[i]);
	}
	
	
	if ( tmp_entry.flags & YKDB_TOKEN_ENC_PASSWORD )
	{
		/* obtain and store the second factor passcode if not already defined */
		password_text = getInput("Password: ", 256, 0);
		
		if (password_text != NULL)
		{
			getSHA256(password_text, strlen(password_text), (uint8_t *)&entry.password_hash);
			safeSnprintfAppend(ticket_enc_key, 256, "|%s", password_text);
		}
	
		if ( memcmp(tmp_entry.password_hash, entry.password_hash, 32) )
			return 1;
	}
	
	safeSnprintfAppend(ticket_enc_key, 256, "|TICKET_ENC_KEY_END");

	getSHA256(ticket_enc_key, strlen(ticket_enc_key), ticket_enc_hash);
	aesDecryptCBC((uint8_t *)&tmp_entry.ticket, sizeof(ykdb_entry_ticket), ticket_enc_key, ticket_enc_key+16);

	return 0;
}

int deleteYubikeyEntry(void)
{
	uint8_t				ticket_enc_key[256];
	uint8_t				ticket_enc_hash[32];
	uint8_t				i;

	ykdb_entry			tmp_entry;

	printf("Deleting Yubikey entry for %s\n", user_text);

	if ( ykdbEntryGet(handle, &tmp_entry) != YKDB_SUCCESS )
		return 1;

	/* decrypt entry as required */
	safeSnprintf(ticket_enc_key, 256, "TICKET_ENC_KEY_BEGIN");

	if ( tmp_entry.flags & YKDB_TOKEN_ENC_PUBLIC_UID )
	{
		safeSnprintfAppend(ticket_enc_key, 256, "|", public_uid_bin);
		for(i=0; i<public_uid_bin_size; i++)
			safeSnprintfAppend(ticket_enc_key, 256, "%02x", public_uid_bin[i]);
	}
	
	if ( tmp_entry.flags & YKDB_TOKEN_ENC_PASSWORD )
	{
		/* obtain and store the second factor passcode if not already defined */
		password_text = getInput("Password: ", 256, 0);
		
		if (password_text != NULL)
		{
			getSHA256(password_text, strlen(password_text), (uint8_t *)&entry.password_hash);
			safeSnprintfAppend(ticket_enc_key, 256, "|%s", password_text);
		}
	
		if ( memcmp(tmp_entry.password_hash, entry.password_hash, 32) )
			return 1;
	}
	
	safeSnprintfAppend(ticket_enc_key, 256, "|TICKET_ENC_KEY_END");

	getSHA256(ticket_enc_key, strlen(ticket_enc_key), ticket_enc_hash);
	aesDecryptCBC((uint8_t *)&tmp_entry.ticket, sizeof(ykdb_entry_ticket), ticket_enc_key, ticket_enc_key+16);

	ykdbPrintEntry(&tmp_entry);

	if ( ykdbEntryDelete(handle) != YKDB_SUCCESS )
	{
		printf("Unable to write to the database: %s [%d]\n", YKDB_FILE, ykdb_errno);
		return 1;
	}

	return 0;
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

/* courtesy myname.c (pam_unix) */
struct passwd *getPWEnt(void)
{
	struct passwd		*pw;
	const char			*cp = getlogin();
	uid_t				ruid = getuid();
		    
    if (cp && *cp && (pw = getpwnam(cp)) && pw->pw_uid == ruid)
		return pw;
						  
    return getpwuid(ruid);
}

