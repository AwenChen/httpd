/*
* utils.h
* including necessary APIs declaration.
*
* Maintainer: awenchen(czw8528@sina.com)
* Date: 2016-09-18
*/

#ifndef __UTILS_H__
#define __UTILS_H__

#include "common.h"

#define SERV_ERR         -100
#define CLIENT_ERR       -1


int get_file_size(const char *file, ull *size);
int send_bytes(int fd, const char *buf, size_t len);
int write_bytes(int fd, const char *buf, size_t len);
int read_bytes(int fd, const char *buf, size_t len);
int parse_key_and_value(const char *line, char *key, char *value);
void copy_string(const char *start, const char *end, char *dst);


#endif

