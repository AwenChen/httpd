/*
* This is a tiny-httpd for download, upload, speed test and error code test!
*
* maintainer awenchen(czw8528@sina.com)
* 2016.09.13
*
* NOTICE: We should set workspace through option '-W, --workspace=', which 
*         would be the prefix path of uri from client request. Otherwise,  
*         of course, we have the default value: "/home".
*
* The directory tree is as follow:
* workspace+--errcode+--200
*          |         +--302
*          |         +--404
*          |            ...
*          +--speedtest+--upload
*          |           +--download
*          +--upload
*          +--download
*
* Client should construct its url as follow:
* (1)If client is for error code test, the url should be:
*          http://ip:port/errcode/404
*    Server would only reply error code in "workspace/errcode/404", then
*    shutdown the connection. Usually, it is "HTTP/1.1 404 Not Found", or
*    other you want.
* (2)For upload or download speed test, the url should be:
*          http://ip:port/speedtest/'*'
*    The star in url means anything you want, we would not create a file,
*    or read from a real file and send it to client. All data is virtual.
* (3)For real upload, it is:
*          http://ip:port/upload/FILE
*    Here, we would create "FILE" in directory "workspace/upload", and fulfill
*    it with what client puts.
* (4)For real download, it should be:
*          http://ip:port/download/FILE
*    We would read "FILE" in directory "workspace/upload", and send it to client.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "common.h"
#include "utils.h"
#include "base64.h"

/*
* definition of macros
*/
#define HTTPD_EOF        "\r\n"
#define SERVER_STRING    "Server: tiny-httpd/1.0.0\r\n"
#define MAX_LISTEN_NUM   100
#define RXTX_BUF_LEN     (8*1024)
#define PTHREAD_STACK_SIZE (2*1024*1024) /* 2M */

/*
* definition of global variables
*/
static int port = 0;
static char putauth = 0;
static char logflag = 0;
static char workspace[PATH_LEN] = "/home";
static char username[KEY_LEN]  = "root";
static char password[KEY_LEN]  = "root";

/*
* declaration of internal functions
*/
static int start_up(int *port);
static int get_line(int sock, char *buf, int size);
static void get_cmd_option(int argc, char **argv);
static void dispatch_request(int client);
static void bad_request(int sock);
static void unauthorized(int sock);
static void not_found(int sock);
static void internal_err(int sock);
static void unimplemented(int sock);
static void error_die(const char *errstr);
static void *handle_req_entry(void *arg);
static void handle_errcode_test(int client, const char *file);
static void handle_get_req(int client, int speedtest, const char *file);
static void handle_put_req(int client, int speedtest, const char *file, ull contentlen);
static void httpd_show_usage(void);


/*
* definition of functions
*/
static void httpd_show_usage()
{
    printf("This is a tiny-httpd for download, upload, speed test and error code test!\n");
    printf("Usage:\n\
        httpd -a -p port -W path -U username -P password\n");
    printf("Options:\n\
        -h, --help            show usage information\n\
        -l, --log             write httpd log to a file [log/httpd.log]\n\
        -a, --auth            this would make httpd server Basic authentication enable,\n\
                              client must provide user authentication information when put request\n\
        -p, --port=PORT       specify httpd listening port\n\
        -U, --username=UN     if need authentication when upload a file, this is the username\n\
        -P, --password=PW     if need authentication when upload a file, this is the password\n\
        -W, --workspace=PATH  specify the prefix path of all file and directory from client request\n");
    printf("\nCopyright (C) CZW 2016.\nAll Rights Reserved.\nawenchen(czw8528@sina.com)\n");
}

static void get_cmd_option(int argc, char **argv)
{
    int cmdline = 0;
    int optindex = -1;
    const char optstring[] = "ahlW:U:P:p:";
    const struct option long_options[] = 
    {
        { "workspace",      1, NULL, 'W' },
        { "username",       1, NULL, 'U' },
        { "password",       1, NULL, 'P' },
        { "port",           1, NULL, 'p' },
        { "auth",           0, NULL, 'a' },
        { "help",           0, NULL, 'h' },
        { "log",            0, NULL, 'l' },
        { 0,                0,    0,   0 }
    };

    while ((cmdline = getopt_long(argc, argv, optstring, long_options, &optindex)) != EOF) 
    {
        switch (cmdline) 
        {
            case 'W': /* set httpd working space */
                if( strlen(optarg) < sizeof(workspace) )
                {
                    if( !access(optarg, F_OK|R_OK|W_OK) )
                    {
                        strcpy(workspace, optarg);

                        if( strlen(workspace) > 1 && workspace[strlen(workspace) - 1] == '/' )
                        {
                            workspace[strlen(workspace) - 1] = 0;
                        }
                    }
                    else
                    {
                        printf("Directory [%s] does not exist or we have no permission to read and write, \
use default directory [%s] instead!\n", optarg, workspace);
                    }
                }
                else
                {
                    printf("Workspace [%s] is illegal: string length is beyond our expectation:\
no more than %u, use default [%s] instead!\n", optarg, sizeof(workspace) - 1, workspace);
                }
                break;
                
            case 'U': /* set httpd uername */
                if( strlen(optarg) < sizeof(username) )
                {
                    strcpy(username, optarg);
                }
                else
                {
                    printf("Username [%s] is illegal: string length is beyond our expectation: no more than %u, \
use default username [%s] instead!\n", optarg, sizeof(username) - 1, username);
                }
                break;
                
            case 'P': /* set httpd password */
                if( strlen(optarg) < sizeof(password) )
                {
                    strcpy(password, optarg);
                }
                else
                {
                    printf("Password [%s] is illegal: string length is beyond our expectation: no more than %u, \
use default password [%s] instead!\n", optarg, sizeof(password) - 1, password);
                }
                break;

            case 'p': /* set httpd listening port */
                port = atoi(optarg);

                if( port > 0xffff || port < 0 )
                {
                    printf("Port [%d] is illegal, the legal range if from %d to %d!\n",
                        port, 0, 0xffff);
                    port = 0;
                }

                if( !port )
                {
                    printf("BE CAREFUL! We would Listen to a Random Port!\n");
                }
                break;

            case 'a':
                putauth = 1;
                break;

            case 'l':
                logflag = 1;
                break;

            case 'h':
            default:
                httpd_show_usage();
                exit(1);
        }
    }
}

static int basic_user_auth(const char *authinfo)
{
    char *ptr = NULL;
    char type[16] = {0};
    char user[VALUE_LEN] = {0};
    char pass[VALUE_LEN] = {0};
    char result[2*VALUE_LEN] = {0};
    
    /*
    * Basic xxxxx=
    */

    if( !(ptr = strchr(authinfo, ' ')) ||
        ptr - authinfo >= sizeof(type) )
    {
        printf("Illegal auth info: %s!\n", authinfo);
        return -1;
    }

    copy_string(authinfo, ptr-1, type);

    /* we only handle Basic authentication */
    if( strcasecmp(type, "Basic") )
    {
        printf("Not Basic auth info: %s!\n", type);
        return -1;
    }

    while( isspace(*ptr) ) ++ptr;
    
    if( !decode_base64((unsigned char *)result, ptr) )
    {
        printf("base64 decode error!\n");
        return -1;
    }

    if( parse_key_and_value(result, user, pass) < 0 )
    {
        return -1;
    }

    /* printf("user: %s, pass: %s\n", user, pass); */

    if( !strcmp(user, username) &&
        !strcmp(pass, password) )
    {
        return 0;
    }
    else
    {
        printf("user auth failed: illegal username or password!\n");
        return -1;
    }
}

static void get_req_info(const char *buf, char *method, char *uri)
{
    int i = 0;
    int j = 0;
    
    /* get method */
    while( buf[j] && !isspace(buf[j]) && i < METHOD_LEN-1 )
    {
        method[i] = buf[j];
        i++; j++;
    }
    method[i] = '\0';

    /* get uri */
    i = 0;
    while( buf[j] && isspace(buf[j]) ) ++j;
    
    while( buf[j] && !isspace(buf[j]) && i < URI_LEN-1 )
    {
        uri[i] = buf[j];
        i++; j++;
    }
    uri[i] = '\0';
}

/*
* handle request entry
*/
static void dispatch_request(int client)
{
    int speedtest = 0;
    ull contentlen = 0;
    char buf[BUF_LEN] = {0};
    char method[METHOD_LEN] = {0};
    char uri[URI_LEN] = {0};
    char file[FILE_LEN] = {0};
    char key[KEY_LEN] = {0};
    char value[VALUE_LEN] = {0};
    char authinfo[VALUE_LEN] = {0};

    if( get_line(client, buf, sizeof(buf)) > 0 )
    {
        get_req_info(buf, method, uri);
    }
    else
    {
        return;
    }

    printf("Recv a request: %s %s!\n", method, uri);

    while( get_line(client, buf, sizeof(buf)) > 0 && strcmp(buf, "\n") != 0 )
    {
        if( buf[strlen(buf) - 1] == '\n' )
            buf[strlen(buf) - 1] = '\0';
        
        if( parse_key_and_value(buf, key, value) < 0 ) /* none-fatal error */
        {
            continue;
        }

        if( !strcasecmp("Content-Length", key) )
        {
            contentlen = strtoull(value, NULL, 10);
        }
        else if( !strcasecmp("Authorization", key) )
        {
            strcpy(authinfo, value);
            /* printf("Auth: %s\n", authinfo); */
        }
    }

    /* joint file = workspace + uri */
    sprintf(file, "%s%s", workspace, uri);
    
    if( !strncmp(uri, "/errcode", 8) ) /* for errcode test */
    {
        handle_errcode_test(client, file);
        return;
    }
    else if( !strncmp(uri, "/speedtest", 10) ) /* for speed test */
    {
        speedtest = 1;
    }

    if( !strcasecmp(method, "PUT") ||
        !strcasecmp(method, "POST") )
    {
        if( putauth && !speedtest )
        {
            if( !strlen(authinfo) )
            {
                printf("No Authorization info!\n");
                unauthorized(client);
                return;
            }

            if( basic_user_auth(authinfo) < 0 )
            {
                printf("Authorization failed!\n");
                unauthorized(client);
                return;
            }
        }
        
        handle_put_req(client, speedtest, file, contentlen);
        return;
    }
    else if( !strcasecmp(method, "GET") )
    {
        handle_get_req(client, speedtest, file);
        return;
    }
    else
    {
        unimplemented(client);
        return;
    }
}

/*
* To test exceptions of client, the server would respond some error code to client.
*/
static void handle_errcode_test(int client, const char *file)
{
    FILE *fp = NULL;
    char buf[BUF_LEN] = {0};

    if( !(fp = fopen(file, "r")) )
    {
        perror("fopen");
        internal_err(client);
        return;
    }

    while( fgets(buf, BUF_LEN, fp) )
    {
        if( buf[strlen(buf)-1] == '\n' )
            buf[strlen(buf)-1] = '\0';
        
        send(client, buf, strlen(buf), 0);
        send(client, HTTPD_EOF, strlen(HTTPD_EOF), 0);
    }
    send(client, HTTPD_EOF, strlen(HTTPD_EOF), 0);
    fclose(fp);
}

/**********************************************************************/
/* Handle get request from client.
 * Parameters: client socket */
/**********************************************************************/
static void handle_get_req(int client, int speedtest, const char *file)
{
    int ret = -1;
    int fd  = -1;
    ull totallen   = 0;
    ull contentlen = 0;
    char buf[RXTX_BUF_LEN] = {0};
    unsigned int sendlen = 0;
    fd_set wrset;
    fd_set tmpset;
    struct timeval tval;
    struct timeval timeout;

    /*
    * If the request is for speed test, then a virtual file would be downloaded.
    */
    if( speedtest )
    {
        contentlen = 0x7fffffff; /* a large file */
    }
    else /* download a real file */
    {
        if( access(file, F_OK|R_OK) < 0 )
        {
            perror("access");
            goto NOT_FOUND;
        }
        
        if( (ret = get_file_size(file, &contentlen)) == SERV_ERR )
        {
            goto INTERNAL_ERR;
        }
        else if( ret == CLIENT_ERR )
        {
            goto BAD_REQ;
        }

        if( (fd = open(file, O_RDONLY)) < 0 )
        {
            perror("open");
            goto INTERNAL_ERR;
        }
    }

    sprintf(buf, "HTTP/1.1 200 OK\r\nContent-Length: %llu\r\n\r\n", contentlen);
    send(client, buf, strlen(buf), 0);
    
    FD_ZERO(&tmpset);
    FD_SET(client, &tmpset);
    
    tval.tv_sec  = SOCKET_TIMEOUT;
    tval.tv_usec = 0;

    sendlen = RXTX_BUF_LEN;
    memset(buf, 0, RXTX_BUF_LEN);
    
    while( 1 )
    {
        wrset = tmpset;
        timeout = tval;

        ret = select(client+1, NULL, &wrset, NULL, &timeout);

        
        if( ret > 0 )
        {
            if( FD_ISSET(client, &wrset) )
            {
                if( !speedtest )
                {
                    sendlen = read(fd, buf, RXTX_BUF_LEN);
                    if( !sendlen )
                    {
                        break;
                    }
                    else if( sendlen < 0 )
                    {
                        perror("read");
                        break;
                    }
                }
                else
                {
                    if( totallen + sendlen > contentlen )
                    {
                        sendlen = contentlen - totallen;
                    }
                }

                if( send_bytes(client, buf, sendlen) == 0 )
                {
                    totallen += sendlen;
                    if( totallen >= contentlen )
                    {
                        break;
                    }
                }
                else
                {
                    break;
                }
            }
        }
        else if( ret == -1 && errno == EINTR ) 
        {
            printf("select interrupted, try again!\n");
        }
        else if( ret == 0 )
        {
            printf("select timeout!\n");
            break;
        }
        else
        {
            perror("select");
            break;
        }
    }

    if( !speedtest )
    {
        close(fd);
    }

    printf("Total sent bytes [%llu].\n", totallen);
    return;
    
BAD_REQ:
    bad_request(client);
    return;
    
NOT_FOUND:
    not_found(client);
    return;

INTERNAL_ERR:
    internal_err(client);
    return;
    
}


/*
* Handle PUT request from client.
* Parameters: client socket, request file and file length
*/
static void handle_put_req(int client, int speedtest, const char *file, ull contentlen)
{
    int ret = -1;
    int fd  = -1;
    ull totallen = 0;
    char *ptr = NULL;
    char buf[RXTX_BUF_LEN] = {0};
    char path[FILE_LEN] = {0};
    unsigned int recvlen  = 0;
    fd_set rdset;
    fd_set tmpset;
    struct timeval tval;
    struct timeval timeout;

    /*
    * If the request is for speed test, then do not create file.
    */
    if( !speedtest ) /* create a real file */
    {
        if( access(file, F_OK) == 0 )
        {
            printf("Now the file [%s] exists, we would cover it...\n", file);
        }
        else /* check if the directory exists and if we have right to write */
        {
            strcpy(path, file);

            if( !(ptr = strrchr(path, '/')) )
            {
                printf("No path!\n");
                goto BAD_REQ;
            }
            *ptr = '\0';

            if( access(path, F_OK|W_OK) < 0 )
            {
                perror("access");
                goto BAD_REQ;
            }
        }

        /* if the file exists we clear it, or creates it */
        if( (fd = creat(file, 0644)) < 0 )
        {
            perror("creat");
            goto INTERNAL_ERR;
        }
    }
    
    strcpy(buf, "HTTP/1.1 201 Created\r\n\r\n");
    send(client, buf, strlen(buf), 0);
    
    FD_ZERO(&tmpset);
    FD_SET(client, &tmpset);
    
    tval.tv_sec  = SOCKET_TIMEOUT;
    tval.tv_usec = 0;
    
    while( 1 )
    {
        rdset = tmpset;
        timeout = tval;
        ret = select(client+1, &rdset, NULL, NULL, &timeout);
        
        if( ret > 0 )
        {
            if( FD_ISSET(client, &rdset) )
            {
                recvlen = recv(client, buf, RXTX_BUF_LEN, 0);
                if( recvlen > 0 )
                {
                    if( !speedtest )
                    {
                        if( write_bytes(fd, buf, recvlen) < 0 )
                        {
                            break;
                        }
                    }

                    totallen += recvlen;

                    if( totallen >= contentlen )
                    {
                        break;
                    }
                }
                else if( !recvlen )
                {
                    break;
                }
                else
                {
                    perror("recv");
                    break;
                }
            }
        }
        else if( ret == -1 && errno == EINTR ) 
        {
            printf("select interrupted, try again!\n");
        }
        else if( ret == 0 )
        {
            printf("select timeout!\n");
            break;
        }
        else
        {
            perror("select");
            break;
        }
    }

    if( !speedtest )
    {
        close(fd);
    }
    
    printf("Total received bytes [%llu].\n", totallen);
    return;

BAD_REQ:
    bad_request(client);
    return;

INTERNAL_ERR:
    internal_err(client);
    return;
    
}

/**********************************************************************/
/* Print out an error message with perror() (for system errors; based
 * on value of errno, which indicates system call errors) and exit the
 * program indicating an error. */
/**********************************************************************/
static void error_die(const char *errstr)
{
    perror(errstr);
    exit(1);
}

/**********************************************************************/
/* Get a line from a socket, whether the line ends in a newline,
 * carriage return, or a CRLF combination.  Terminates the string read
 * with a null character.  If no newline indicator is found before the
 * end of the buffer, the string is terminated with a null.  If any of
 * the above three line terminators is read, the last character of the
 * string will be a linefeed and the string will be terminated with a
 * null character.
 * Parameters: the socket descriptor
 *             the buffer to save the data in
 *             the size of the buffer
 * Returns: the number of bytes stored (excluding null) */
/**********************************************************************/
static int get_line(int sock, char *buf, int size)
{
    int i = 0;
    int n = 0;
    char c = '\0';

    while( i < size - 1 && c != '\n' )
    {
        n = recv(sock, &c, 1, 0);

        if( n > 0 )
        {
            if( c == '\r' )
            {
                n = recv(sock, &c, 1, MSG_PEEK);

                if( n > 0 && c == '\n' )
                {
                    recv(sock, &c, 1, 0);
                }
                else
                {
                    c = '\n';
                }
            }
            
            buf[i] = c;
            i++;
        }
        else
        {
            c = '\n';
        }
    }
    
    buf[i] = '\0';
    return i;
}

/*
* 400 Bad Request
* Inform the client that a request it has made has a problem.
*/
static void bad_request(int sock)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.1 400 BAD REQUEST\r\n");
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, "<P>You sent a bad request, ");
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, "such as a POST without a Content-Length.\r\n");
    send(sock, buf, strlen(buf), 0);
}

/*
* 401 Unauthorized
* Give client a 401 unauthorized status message.
*/
static void unauthorized(int sock)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.1 401 UNAUTHORIZED\r\n");
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(sock, buf, strlen(buf), 0);
}

/*
* 404 Not Found
* Give client a 404 not found status message.
*/
static void not_found(int sock)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.1 404 NOT FOUND\r\n");
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><TITLE>Not Found</TITLE>\r\n");
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>The server could not fulfill\r\n");
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, "your request because the resource specified\r\n");
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, "is unavailable or nonexistent.\r\n");
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    send(sock, buf, strlen(buf), 0);
}

/*
* 500 Internal Error
* Inform the client that a request could not be executed or something wrong with server.
*/
static void internal_err(int sock)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.1 500 Internal Server Error\r\n");
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, "<P>Something Wrong with Server.\r\n");
    send(sock, buf, strlen(buf), 0);
}

/*
* 501 Method Unimplemented
* Inform the client that the requested web method has not been implemented.
*/
void unimplemented(int sock)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 501 Method Not Implemented\r\n");
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><HEAD><TITLE>Method Not Implemented\r\n");
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, "</TITLE></HEAD>\r\n");
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>HTTP request method not supported, please try GET/PUT/POST.\r\n");
    send(sock, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    send(sock, buf, strlen(buf), 0);
}

/**********************************************************************/
/* This function starts the process of listening for web connections
 * on a specified port.  If the port is 0, then dynamically allocate a
 * port and modify the original port variable to reflect the actual
 * port.
 * Parameters: pointer to variable containing the port to connect on
 * Returns: the socket */
/**********************************************************************/
static int start_up(int *port)
{
    int sock = 0;
    struct sockaddr_in serv;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if( sock == -1 )
    {
        error_die("socket");
    }
    
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_port = htons(*port);
    serv.sin_addr.s_addr = htonl(INADDR_ANY);
    
    if( bind(sock, (struct sockaddr *)&serv, sizeof(serv)) < 0)
    {
        error_die("bind");
    }
    
    if( *port == 0 )  /* if dynamically allocating a port */
    {
        socklen_t len = sizeof(serv);
        if( getsockname(sock, (struct sockaddr *)&serv, &len) == -1 )
        {
            error_die("getsockname");
        }
        *port = ntohs(serv.sin_port);
    }
    
    if( listen(sock, MAX_LISTEN_NUM) < 0 )
    {
        error_die("listen");
    }
    
    return sock;
}

static void *handle_req_entry(void *arg)
{
    dispatch_request((int)arg);

    close((int)arg);

    return NULL;
}

static pthread_attr_t *pthread_attr_set()
{
    pthread_attr_t *pattr = (pthread_attr_t *)malloc(sizeof(pthread_attr_t));

    if( !pattr )
    {
        perror("malloc");
        return NULL;
    }
    
    if( pthread_attr_init(pattr) )
    {
        perror("pthread_attr_init");
        goto SET_FAILED;
    }

    if( pthread_attr_setstacksize(pattr, PTHREAD_STACK_SIZE) )
    {
        perror("pthread_attr_setstacksize");
        goto SET_FAILED;
    }

    /* 
    * detach child thread from primary thread
    * so, child thread's resource would be free when it's over.
    */
    if( pthread_attr_setdetachstate(pattr, PTHREAD_CREATE_DETACHED) )
    {
        perror("pthread_attr_setdetachstate");
        goto SET_FAILED;
    }

    return pattr;
    
SET_FAILED:
    free(pattr);
    return NULL;
}

/*
* httpd entry
*/
int main(int argc, char *argv[])
{
    int server_sock = -1;
    int client_sock = -1;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    pthread_t newthread = -1;
    pthread_attr_t *pattr = NULL;

    get_cmd_option(argc, argv);

    server_sock = start_up(&port);
    printf("httpd is running on port [%d]\n", port);

    pattr = pthread_attr_set();

    while( 1 )
    {
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_addr_len);

        if( client_sock >= 0 )
        {
            if( pthread_create(&newthread, pattr, handle_req_entry, (void *)client_sock) < 0 )
            {
                perror("pthread_create");
            }
        }
        else
        {
            /* non-fatal error, try again */
            if( errno == EINTR ||
                errno == EAGAIN || 
                errno == ECONNABORTED )
            {
                continue;
            }
            else
            {
                error_die("accept");
            }
        }
    }

    close(server_sock);
    
    if( pattr )
    {
        pthread_attr_destroy(pattr);
        free(pattr);
    }

    return 0;
}

