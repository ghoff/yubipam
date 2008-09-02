/*
* YubiKey DB API
*
* Copyright (C) 2008 SecurixLive	dev@securixlive.com
* Copyright (C) 2008 Ian Firns		firnsy@securixlive.com
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

#include <stdio.h>
#include <stdlib.h> /* malloc free */
#include <string.h> /* memcmp */

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "yubikey_db.h"


#define YKDB_ERROR(code) ykdb_errno=code
#define YKDB_ERROR_RET(code) ykdb_errno=code; return code;

struct _ykdb_handle {
	int					file_descriptor;
	int					cur_entry;
	ykdb_header			header;
};

int ykdb_errno = 0;

/* private DB functions */
void header2NBO(ykdb_header *header)
{
	header->entry_count = htonl(header->entry_count);
}

void header2HBO(ykdb_header *header)
{
	header->entry_count = ntohl(header->entry_count);
}

void entry2NBO(ykdb_entry *entry)
{
	entry->ticket.last_use = htons(entry->ticket.last_use);
	entry->ticket.last_timestamp_lo = htons(entry->ticket.last_timestamp_lo);
}

void entry2HBO(ykdb_entry *entry)
{
	entry->ticket.last_use = ntohs(entry->ticket.last_use);
	entry->ticket.last_timestamp_lo = ntohs(entry->ticket.last_timestamp_lo);
}

/* public API implementation */
ykdb_h *ykdbDatabaseOpen(const char *path)
{
	struct _ykdb_handle	*handle;
	
	/* check argument sanity */
	if (path == NULL)
	{
		YKDB_ERROR(YKDB_ERR_ARGS);
		return NULL;	
	}

	/* allocate the db handle */
	handle = (struct _ykdb_handle *)malloc(sizeof(struct _ykdb_handle));
	if (handle == NULL)
	{
		return NULL;
	}
	
	/* open the db */
	handle->file_descriptor = open(path, O_RDWR);
	if (handle->file_descriptor == -1)
	{
		free(handle);

		YKDB_ERROR(YKDB_ERR_IO);
		return NULL;
	}

	/* lock the db for writing */
	if ( lockf(handle->file_descriptor, F_LOCK, 0) == -1 )
	{
		close(handle->file_descriptor);
		free(handle);
		
		YKDB_ERROR(YKDB_ERR_LOCK);
		return NULL;
	}

	/* read header */
	if ( read(handle->file_descriptor, &handle->header, sizeof(ykdb_header)) != sizeof (ykdb_header) )
	{
		close(handle->file_descriptor);
		free(handle);

		YKDB_ERROR(YKDB_ERR_IO);
		return NULL;
	}

	header2HBO(&handle->header);

	/* check magic and version compatibility */
	if ( memcmp(&handle->header.magic, YKDB_MAGIC, YKDB_MAGIC_SIZE) != 0 ||
		 handle->header.version < YKDB_VERSION )
	{
		close(handle->file_descriptor);
		free(handle);
		
		YKDB_ERROR(YKDB_ERR_DB_INV);
		return NULL;
	}

	return handle;
}

ykdb_h *ykdbDatabaseCreate(const char *path)
{
	struct _ykdb_handle	*handle;
	
	/* check argument sanity */
	if (path == NULL)
	{
		YKDB_ERROR(YKDB_ERR_ARGS);
		return NULL;	
	}

	/* allocate the db handle */
	handle = (struct _ykdb_handle *)malloc(sizeof(struct _ykdb_handle));
	if (handle == NULL)
	{
		return NULL;
	}

	/* create the database file */
	handle->file_descriptor = open(path, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (handle->file_descriptor == -1)
	{
		free(handle);
		YKDB_ERROR(YKDB_ERR_IO);
		return NULL;
	}

	/* lock the db for writing */
	if ( lockf(handle->file_descriptor, F_LOCK, 0) == -1 )
	{
		close(handle->file_descriptor);
		free(handle);
		YKDB_ERROR(YKDB_ERR_LOCK);
		return NULL;
	}
	
	handle->cur_entry = 0;

	/* build the header */
	memcpy(handle->header.magic, YKDB_MAGIC, YKDB_MAGIC_SIZE);
	handle->header.version = YKDB_VERSION;
	handle->header.entry_count = 0;

	/* write the header to disk */
	ykdbHeaderWrite(handle);

	return handle;
}

int ykdbDatabaseClose(ykdb_h *handle)
{
	int ret;

	/* check arguments sanity */
	if (!handle) 
	{
		YKDB_ERROR_RET(YKDB_ERR_ARGS);
	}

	/* write header to disk */
	if ( ( ret=ykdbHeaderWrite(handle) ) != 0 )
	{
		return ret;
	}
															
	/* close the file descriptor*/
	if ( close(handle->file_descriptor) != 0 )
	{
		YKDB_ERROR_RET(YKDB_ERR_IO);
	}

	/* free handle */
	free(handle);

	return YKDB_SUCCESS;
}

int ykdbEntryNext(ykdb_h *handle)
{
	/* check arguments sanity */
	if (handle == NULL) 
	{
		YKDB_ERROR_RET(YKDB_ERR_ARGS);
	}
	
	/* check if databse is empty */
	if (handle->header.entry_count == 0)
	{
		YKDB_ERROR_RET(YKDB_ERR_DB_EMPTY);
	}

	/* check were not already at the end */	
	if (handle->cur_entry == (handle->header.entry_count-1))
	{
		YKDB_ERROR_RET(YKDB_ERR_SEEK);
	}

	/* seek to next entry */
	if ( lseek(handle->file_descriptor, sizeof(ykdb_entry), SEEK_CUR) == -1)
	{
		YKDB_ERROR_RET(YKDB_ERR_IO);	
	}

	/* update handle */
	handle->cur_entry++;

	return YKDB_SUCCESS;
}

int ykdbEntryPrev(ykdb_h *handle)
{
	/* check arguments sanity */
	if (handle == NULL) 
	{
		YKDB_ERROR_RET(YKDB_ERR_ARGS);
	}
	
	/* check if databse is empty */
	if (handle->header.entry_count == 0)
	{
		YKDB_ERROR_RET(YKDB_ERR_DB_EMPTY);
	}

	/* check were not already at the beginning */	
	if (handle->cur_entry == 0)
	{
		YKDB_ERROR_RET(YKDB_ERR_SEEK);
	}

	/* seek to next entry */
	if ( lseek(handle->file_descriptor, -sizeof(ykdb_entry), SEEK_CUR) == -1)
	{
		YKDB_ERROR_RET(YKDB_ERR_IO);	
	}

	/* update handle */
	handle->cur_entry--;

	return YKDB_SUCCESS;
}

int ykdbEntryGet(ykdb_h *handle, ykdb_entry *entry)
{
	int ret;
	/* check arguments sanity */
	if (handle == NULL || entry == NULL) 
	{
		YKDB_ERROR_RET(YKDB_ERR_ARGS);
	}

	/* check if databse is empty */
	if (handle->header.entry_count == 0)
	{
		YKDB_ERROR_RET(YKDB_ERR_DB_EMPTY);
	}

	/* read entry from disk */
	if ( (ret=read(handle->file_descriptor, entry, sizeof(ykdb_entry))) != sizeof(ykdb_entry))
	{
		YKDB_ERROR_RET(YKDB_ERR_IO);
	}

	entry2HBO(entry);

	/* rewind file position since a get does not increment */
	if ( lseek(handle->file_descriptor, -sizeof(ykdb_entry), SEEK_CUR) == -1)
	{
		YKDB_ERROR_RET(YKDB_ERR_IO);	
	}

	return YKDB_SUCCESS;
}

int ykdbEntrySeekOnIndex(ykdb_h *handle, uint32_t idx)
{
	uint32_t			file_seek_position;

	/* check arguments sanity */
	if (handle == NULL || idx < 0) 
	{
		YKDB_ERROR_RET(YKDB_ERR_ARGS);
	}
	
	/* check if databse is empty */
	if (handle->header.entry_count == 0)
	{
		YKDB_ERROR_RET(YKDB_ERR_DB_EMPTY);
	}

	/* calculate seek position and go there */
	file_seek_position = sizeof(ykdb_header) + (idx * sizeof(ykdb_entry));

	if ( lseek(handle->file_descriptor, file_seek_position, SEEK_SET) == -1)
	{
		YKDB_ERROR_RET(YKDB_ERR_IO);	
	}

	/* update handle */
	handle->cur_entry = idx;

	return YKDB_SUCCESS;
}

int ykdbEntryGetIndex(ykdb_h *handle, uint32_t *idx)
{
	/* check arguments sanity */
	if (handle == NULL || idx == NULL) 
	{
		YKDB_ERROR_RET(YKDB_ERR_ARGS);
	}
	
	/* check if databse is empty */
	if (handle->header.entry_count == 0)
	{
		YKDB_ERROR_RET(YKDB_ERR_DB_EMPTY);
	}

	*idx = handle->cur_entry;
	
	return YKDB_SUCCESS;
}

int ykdbEntryDelete(ykdb_h *handle)
{
	uint32_t			file_seek_position;
	ykdb_entry			empty_entry;

	/* check arguments sanity */
	if (handle == NULL) 
	{
		YKDB_ERROR_RET(YKDB_ERR_ARGS);
	}

	/* set all values to ff */
	memset(&empty_entry, 0xff, sizeof(ykdb_entry));

	/* write empty entry to disk */
	if ( write(handle->file_descriptor, &empty_entry, sizeof(ykdb_entry)) != sizeof(ykdb_entry) )
	{
		YKDB_ERROR_RET(YKDB_ERR_IO);
	}

	/* update the header */
	handle->header.entry_count--;

	/* reset seek pointer to end of header */
	file_seek_position = sizeof(ykdb_header);
	handle->cur_entry = -1;

	if ( lseek(handle->file_descriptor, file_seek_position, SEEK_SET) == -1)
	{
		YKDB_ERROR_RET(YKDB_ERR_IO);
	}

	/* reset back to zero */
	return YKDB_SUCCESS;
}

int ykdbEntryAdd(ykdb_h *handle, ykdb_entry *entry)
{
	/* check arguments sanity */
	if (handle == NULL || entry == NULL) 
	{
		YKDB_ERROR_RET(YKDB_ERR_ARGS);
	}

	/* search for a previously deleted entry (ie. empty entry) */
	if ( ykdbEntrySeekEmpty(handle) != YKDB_SUCCESS )
	{
		/* add to end of file */
		if ( lseek(handle->file_descriptor, 0, SEEK_END) == -1 )
		{
			YKDB_ERROR_RET(YKDB_ERR_IO);
		}
	}

	entry2NBO(entry);

	/* write entry to disk */
	if ( write(handle->file_descriptor, entry, sizeof(ykdb_entry)) != sizeof(ykdb_entry) )
	{
		YKDB_ERROR_RET(YKDB_ERR_IO);
	}

	entry2HBO(entry);

	/* update the header */
	handle->header.entry_count++;
	
	return ykdbEntrySeekOnIndex(handle, handle->cur_entry);
}

int ykdbEntryAdd2(ykdb_h *handle, uint8_t *public_uid_hash, uint8_t *password_hash, uint8_t flags, ykdb_entry_ticket *tkt)
{
	ykdb_entry			tmp_entry;
	
	/* check arguments sanity */
	if (handle == NULL || public_uid_hash == NULL || tkt == NULL) 
	{
		YKDB_ERROR_RET(YKDB_ERR_ARGS);
	}
	
	/* build entry structure */
	memcpy(&tmp_entry.public_uid_hash, public_uid_hash, 32);
	memcpy(&tmp_entry.password_hash, password_hash, 32);
	tmp_entry.flags = flags;
	memcpy(&tmp_entry.ticket, tkt, sizeof(ykdb_entry_ticket));

	return ykdbEntryAdd(handle, &tmp_entry);
}

int ykdbEntryWrite(ykdb_h *handle, ykdb_entry *entry)
{
	/* check arguments sanity */
	if (handle == NULL || entry == NULL) 
	{
		YKDB_ERROR_RET(YKDB_ERR_ARGS);
	}
	
	/* check if databse is empty */
	if (handle->header.entry_count == 0)
	{
		YKDB_ERROR_RET(YKDB_ERR_DB_EMPTY);
	}

	entry2NBO(entry);

	/* write entry to disk */
	if ( write(handle->file_descriptor, entry, sizeof(ykdb_entry)) != sizeof(ykdb_entry) )
	{
		YKDB_ERROR_RET(YKDB_ERR_IO);
	}

	entry2HBO(entry);

	return YKDB_SUCCESS;

}

int ykdbHeaderWrite(ykdb_h *handle)
{
	off_t				old_pos;

	/* check arguments sanity */
	if (handle == NULL) 
	{
		YKDB_ERROR_RET(YKDB_ERR_ARGS);
	}
	
	old_pos = lseek(handle->file_descriptor, 0, SEEK_CUR);

	/* seek to database header (ie. start of file) */
	if ( lseek(handle->file_descriptor, 0, SEEK_SET) == -1 )
	{
		YKDB_ERROR_RET(YKDB_ERR_IO);
	}

	header2NBO(&handle->header);

	/* write header to disk */
	if ( write(handle->file_descriptor, &handle->header, sizeof(ykdb_header)) != sizeof(ykdb_header) )
	{
		YKDB_ERROR_RET(YKDB_ERR_IO);
	}

	header2HBO(&handle->header);
	
	/* return to old position */
	if ( lseek(handle->file_descriptor, old_pos, SEEK_SET) == -1 )
	{
		YKDB_ERROR_RET(YKDB_ERR_IO);
	}

	return YKDB_SUCCESS;
}

int ykdbEntrySeekEmpty(ykdb_h *handle)
{
	int					i;
	off_t				old_pos;
	ykdb_entry			entry;

	/* check argument sanity */
	if (handle == NULL)
	{
		YKDB_ERROR_RET(YKDB_ERR_ARGS);
	}
	
	/* check if databse is empty */
	if (handle->header.entry_count == 0)
	{
		YKDB_ERROR_RET(YKDB_ERR_DB_EMPTY);
	}

	/* start at beginning of database */
	if ( ykdbEntrySeekOnIndex(handle, 0) != YKDB_SUCCESS )
	{
		YKDB_ERROR_RET(YKDB_ERR_IO);
	}

	/* loop looking for public hash match */
	for (i=0; i<handle->header.entry_count; i++, ykdbEntryNext(handle) )
	{
		ykdbEntryGet(handle, &entry);

		if ( entry.flags == 0xff )
		{
			return YKDB_SUCCESS;
		}
	}

	return YKDB_ERR_SEEK;
}

/* Extended functions */
int ykdbEntrySeekOnUserHash(ykdb_h *handle, uint8_t *user_hash)
{
	int					i;
	off_t				old_pos;
	ykdb_entry			entry;

	/* check argument sanity */
	if (handle == NULL || user_hash == NULL)
	{
		YKDB_ERROR_RET(YKDB_ERR_ARGS);
	}
	
	/* check if databse is empty */
	if (handle->header.entry_count == 0)
	{
		YKDB_ERROR_RET(YKDB_ERR_DB_EMPTY);
	}

	/* save old position in case of fail */
	old_pos = lseek(handle->file_descriptor, 0, SEEK_CUR);

	/* start at beginning of database */
	if ( ykdbEntrySeekOnIndex(handle, 0) != YKDB_SUCCESS )
	{
		YKDB_ERROR_RET(YKDB_ERR_IO);
	}

	/* loop looking for public hash match */
	for (i=0; i<handle->header.entry_count; i++, ykdbEntryNext(handle) )
	{
		ykdbEntryGet(handle, &entry);

		if ( memcmp(entry.user_hash, user_hash, 32) == 0 )
		{
			return YKDB_SUCCESS;
		}
	}

	/* since the record was not found, return to old position */
	if ( lseek(handle->file_descriptor, old_pos, SEEK_SET) == -1 )
	{
		YKDB_ERROR_RET(YKDB_ERR_IO);
	}

	return YKDB_ERR_SEEK;
}

int ykdbEntrySeekOnPublicHash(ykdb_h *handle, uint8_t *public_uid_hash)
{
	int					i;
	off_t				old_pos;
	ykdb_entry			entry;

	/* check argument sanity */
	if (handle == NULL || public_uid_hash == NULL)
	{
		YKDB_ERROR_RET(YKDB_ERR_ARGS);
	}
	
	/* check if databse is empty */
	if (handle->header.entry_count == 0)
	{
		YKDB_ERROR_RET(YKDB_ERR_DB_EMPTY);
	}

	/* save old position in case of fail */
	old_pos = lseek(handle->file_descriptor, 0, SEEK_CUR);

	/* start at beginning of database */
	if ( ykdbEntrySeekOnIndex(handle, 0) != YKDB_SUCCESS )
	{
		YKDB_ERROR_RET(YKDB_ERR_IO);
	}

	/* loop looking for public hash match */
	for (i=0; i<handle->header.entry_count; i++, ykdbEntryNext(handle) )
	{
		ykdbEntryGet(handle, &entry);

		if ( memcmp(entry.public_uid_hash, public_uid_hash, 32) == 0 )
		{
			return YKDB_SUCCESS;
		}
	}

	/* since the record was not found, return to old position */
	if ( lseek(handle->file_descriptor, old_pos, SEEK_SET) == -1 )
	{
		YKDB_ERROR_RET(YKDB_ERR_IO);
	}

	return YKDB_ERR_SEEK;
}

uint32_t ykdbDatabaseEntryCountGet(ykdb_h *handle)
{
	/* check argument sanity */
	if (handle == NULL)
	{
		return -1;
	}

	return handle->header.entry_count;
}

void ykdbPrintEntry(ykdb_entry *entry)
{
	int i;
	
	printf("ykdb_entry {\n");
    printf("  user_hash           = ");
    for (i=0; i<32; i++)
		printf("%02x ", entry->user_hash[i]);
	printf("\n");
    printf("  public_uid_hash     = ");
    for (i=0; i<32; i++)
		printf("%02x ", entry->public_uid_hash[i]);
	printf("\n");
	printf("  password_hash       = ");
	for (i=0; i<32; i++)
		printf("%02x ", entry->password_hash[i]);
	printf("\n");
	printf("  flags               = %02x\n", entry->flags);
	printf("  ticket {\n");
	printf("    key               = ");
	for (i=0; i<16; i++)
		printf("%02x ", entry->ticket.key[i]);
	printf("\n");
	printf("    private_uid_hash  = ");
	for (i=0; i<32; i++)
		printf("%02x ", entry->ticket.private_uid_hash[i]);
    printf("\n");
	printf("    last_use          = %04x\n", entry->ticket.last_use);
	printf("    last_timestamp_lo = %04x\n", entry->ticket.last_timestamp_lo);
    printf("    last_timestamp_hi = %02x\n", entry->ticket.last_timestamp_hi);
    printf("    last_session      = %02x\n", entry->ticket.last_session);
	printf("  }\n");
	printf("}\n");
}


