/*
* Copyright (C) CZW. 2016
* bnd_utils.c
* including necessary APIs definition.
*
* Maintainer: awenchen(czw8528@sina.com)
* Date: 2016-09-18
*/

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "utils.h"



void copy_string(const char *start, const char *end, char *dst)
{
    while( *start && start <= end )
        *dst++ = *start++;

    *dst = '\0'; /* terminal char */
}

/*
* parse key and value from a string line "  key  :  value  "
* we must strip the space in front/end of the key/value
*/
int parse_key_and_value(const char *line, char *key, char *value)
{
    const char *pks = NULL; /* key start pointer   */
    const char *pke = NULL; /* key end pointer     */
    const char *pvs = NULL; /* value start pointer */
    const char *pve = NULL; /* value end pointer   */

    pks = line;
    while( isspace(*pks) ) ++pks;

    pvs = strchr(pks, ':');
    if( !pvs )
    {
        return -1;
    }
    pke = pvs - 1;
    ++pvs;

    while( isspace(*pvs) ) ++pvs;
    while( isspace(*pke) ) --pke;

    pve = &line[strlen(line) - 1];
    while( isspace(*pve) ) --pve;

    if( pke - pks >= KEY_LEN )
    {
        printf("key length beyond limit!\n");
        return -1;
    }
    
    if( pve - pvs >= VALUE_LEN )
    {
        printf("value length beyond limit!\n");
        return -1;
    }
    
    copy_string(pks, pke, key);
    copy_string(pvs, pve, value);

    return 0;
}

/*
* We must confirm whether the file is a regular file, if that we could get its size.
*/
int get_file_size(const char *file, ull *size)
{
    struct stat fst;

    if( stat(file, &fst) < 0 )
    {
        perror("stat");
        return SERV_ERR;
    }

    if( !S_ISREG(fst.st_mode) )
    {
        printf("Not a regular file: %s!\n", file);
        return CLIENT_ERR;
    }

    *size = fst.st_size;
    return 0;
}

int send_bytes(int fd, const char *buf, size_t len)
{
    int wrlen = 0;
    int offset = 0;
    while( len )
    {
        if( (wrlen = send(fd, buf+offset, len, 0)) > 0 )
        {
            len    -= wrlen;
            offset += wrlen;
        }
        else if( wrlen == -1 )
        {
            if( errno == EINTR )
            {
                continue;
            }
            else
            {
                perror("send");
                return -1;
            }
        }
    }

    return 0;
}

int write_bytes(int fd, const char *buf, size_t len)
{
    int wrlen = 0;
    int offset = 0;
    while( len )
    {
        if( (wrlen = write(fd, buf+offset, len)) > 0 )
        {
            len    -= wrlen;
            offset += wrlen;
        }
        else if( wrlen == -1 )
        {
            if( errno == EINTR )
            {
                continue;
            }
            else
            {
                perror("write");
                return -1;
            }
        }
    }

    return 0;
}

int read_bytes(int fd, const char *buf, size_t len)
{
    int wrlen = 0;
    int offset = 0;
    while( len )
    {
        if( (wrlen = read(fd, (void *)buf+offset, len)) > 0 )
        {
            len    -= wrlen;
            offset += wrlen;
        }
        else if( wrlen == -1 )
        {
            if( errno == EINTR )
            {
                continue;
            }
            else
            {
                perror("read");
                return -1;
            }
        }
        else /* EOF */
        {
            break;
        }
    }

    return offset;
}

