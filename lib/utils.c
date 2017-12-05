#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "vars.h"
#include "utils.h"

struct sockaddr new_addr(uint32_t inaddr, unsigned short port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(inaddr);
    addr.sin_port = htons(port);
    return *(struct sockaddr *)&addr;
}

int new_server(uint32_t inaddr, uint16_t port, int backlog) {
    int ret = 0;
    int server;
    server = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr addr = new_addr(inaddr, port);
    if (bind(server, &addr, sizeof(addr)) < 0) {
        return -2;
    }
    if (listen(server, backlog) < 0) {
        return -3;
    }
    return server;
}

/**
 * new client 
 * @return {int} status, -2 create socket error, -1 connect error
 */
int new_client(uint32_t srv_addr, unsigned short port) {
    int client = socket(AF_INET, SOCK_STREAM, 0);
    if (client < 0) return -2;
    struct sockaddr server = new_addr(srv_addr, port);
    int st = connect(client, &server, sizeof(server));
    if (st < 0) return -1;
    return client;
}

int send_str(int peer, const char* fmt, ...) {
    va_list args;
    char msgbuf[BUF_SIZE];
    va_start(args, fmt);
    vsnprintf(msgbuf, sizeof(msgbuf), fmt, args);
    va_end(args);
    return send(peer, msgbuf, strlen(msgbuf), 0);
}

/**
 * -1 error, 0 ok
 */
int send_file(int peer, FILE *f) {
    char filebuf[BUF_SIZE+1];
    int n, ret = 0;
    while ((n=fread(filebuf, 1, BUF_SIZE, f)) > 0) {
        int st = send(peer, filebuf, n, 0);
        if (st < 0) {
            err(1, "send file error, errno = %d, %s", errno, strerror(errno));
            ret = -1;
            break;
        } else {
            filebuf[n] = 0;
            info(1, " %d bytes sent", st);
        }
    }
    return ret;
}

/*
 *
 *  -1 error opening file, -2 send file error, -3 close file error
 */
int send_path(int peer, char *file, uint32_t offset,char *hash) {
//    printf("%s\n",file);
	FILE *f = fopen(file, "rb");
    fseek(f, 0, SEEK_END);
    int size = ftell(f);
    char* data = NULL;
	data = (char*)calloc((size+1), sizeof(char));
	for(int i = 0; size+1 > i; i++) data[i] = '\0';
    fread(data, 1, size, f);
    integrity_check(data, hash);
    printf("Hash Value : %s\n", hash);
	fclose(f);

	f = fopen(file, "rb");
    if (f) {
        fseek(f, offset, SEEK_SET);
        int st = send_file(peer, f);
        if (st < 0) {
            return -2;
        }
    } else {
        return -1;
    }
    int ret = fclose(f);
    return ret == 0 ? 0 : -3;
}

int recv_file(int peer, FILE *f) {
    char filebuf[BUF_SIZE];
    int n;
    while ((n=recv(peer, filebuf, BUF_SIZE, 0)) > 0) {
        fwrite(filebuf, 1, n, f);
    }
    return n;
}

/**
 * recv file by file path
 * @param {int} peer, peer socket
 * @param {char *} file path
 * @param {int} offset
 * @return {int} status, 
 *              -1 means recv_file error, 
 *              -2 means file open failure, 
 *              EOF means close file error
 * 
 */
int recv_path(int peer, char *file, uint32_t offset) {
    FILE *f = fopen(file, "wb");
    if (!f) return -2;
    fseek(f, offset, SEEK_SET);
    int st = recv_file(peer, f);
    int cl = fclose(f);
    return st < 0 ? st : cl;
}

int parse_number(const char *buf, uint32_t *number) {
    int f = -1, i;
    char tmp[BUF_SIZE] = {0};
    int ret = -1;
    for (i=0; buf[i]!=0 && i<BUF_SIZE; i++) {
        if (!isdigit(buf[i])) {
            if (f >= 0) {
                memcpy(tmp, &buf[f], i-f);
                tmp[i-f] = 0;
                *number = atoi(tmp);
                ret = 0;
                f = -1;
                break;
            }
        } else {
            if (f < 0) {
                f = i;
            }
        }
    }
    return ret;
}

int parse_addr_port(const char *buf, uint32_t *addr, uint16_t *port) {
    int i;
    *addr = *port = 0;
    int f = -1;
    char tmp[BUF_SIZE] = {0};
    int cnt = 0;
    int portcnt = 0;
    for(i=0; buf[i]!=0 && i<BUF_SIZE; i++) {
        if(!isdigit(buf[i])) {
            if (f >= 0) {
                memcpy(tmp, &buf[f], i-f);
                tmp[i-f] = 0;
                if (cnt < 4) {
                    *addr = (*addr << 8) + (0xff & atoi(tmp));
                    cnt++;
                } else if (portcnt < 2) {
                    *port = (*port << 8) + (0xff & atoi(tmp));
                    portcnt++;
                } else {
                    break;
                }
                f = -1;
            }
        } else {
            if (f < 0) {
                f = i;
            }
        }
    }
    return cnt == 4 && portcnt == 2;
}

char * parse_path(const char *buf) {
    char * path = (char *)malloc(BUF_SIZE);
    int i, j;
    for (i=0; buf[i]!=' ' && i < BUF_SIZE; i++);
    if (i == BUF_SIZE) return NULL;
    i++;
    for (j=i; buf[j]!='\r' && buf[j]!= '\n' && j < BUF_SIZE; j++);
    memcpy(path, &buf[i], j-i);
    path[j-i] = 0;
    return path;
}

char * n2a(uint32_t addr) {
    uint32_t t = htonl(addr);
    return inet_ntoa(*(struct in_addr *)&t);
}

/**
 * MD5 Hash Algorithm
 *
 */

const uint32_t k[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };
 
const uint32_t r[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	              5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
	              4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	              6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
 
void to_bytes(uint32_t val, uint8_t *bytes)
{
    bytes[0] = (uint8_t) val;
    bytes[1] = (uint8_t) (val >> 8);
    bytes[2] = (uint8_t) (val >> 16);
    bytes[3] = (uint8_t) (val >> 24);
}
 
uint32_t to_int32(const uint8_t *bytes)
{
    return (uint32_t) bytes[0]
	| ((uint32_t) bytes[1] << 8)
	| ((uint32_t) bytes[2] << 16)
	| ((uint32_t) bytes[3] << 24);
}
 
void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest) {
 
    uint32_t h0, h1, h2, h3;
    uint8_t *msg = NULL;
    size_t new_len, offset;
    uint32_t w[16];
    uint32_t a, b, c, d, i, f, g, temp;

    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;
 
    for (new_len = initial_len + 1; new_len % (512/8) != 448/8; new_len++);
 
    msg = (uint8_t*)malloc(new_len + 8);
    memcpy(msg, initial_msg, initial_len);
    msg[initial_len] = 0x80;
    for (offset = initial_len + 1; offset < new_len; offset++)
	msg[offset] = 0;

    to_bytes(initial_len*8, msg + new_len);
    to_bytes(initial_len>>29, msg + new_len + 4);

    for(offset=0; offset<new_len; offset += (512/8)) {
	for (i = 0; i < 16; i++)
	    w[i] = to_int32(msg + offset + i*4);

	a = h0;
	b = h1;
	c = h2;
	d = h3;
 
	for(i = 0; i<64; i++) {
 
	    if (i < 16) {
	        f = (b & c) | ((~b) & d);
	        g = i;
	    } else if (i < 32) {
	        f = (d & b) | ((~d) & c);
	        g = (5*i + 1) % 16;
	    } else if (i < 48) {
	        f = b ^ c ^ d;
	        g = (3*i + 5) % 16;          
	    } else {
	        f = c ^ (b | (~d));
	        g = (7*i) % 16;
	    }
 
	    temp = d;
	    d = c;
	    c = b;
	    b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
	    a = temp;
 
	}

	h0 += a;
	h1 += b;
	h2 += c;
	h3 += d;
    }

    free(msg);

    to_bytes(h0, digest);
    to_bytes(h1, digest + 4);
    to_bytes(h2, digest + 8);
    to_bytes(h3, digest + 12);
}

/**
 * File Integrity
 *
 */
void integrity_check(char* data, char *hash)
{
    uint8_t result[16];
    char tmp[5];
    int i;
    hash[0] = '\0';

    for(i = 0; i < 1000; i++) {
		md5((uint8_t*)data, strlen(data), result);
    }
    for(i = 0; i < 16; i++) {
		sprintf(tmp, "%2.2x", result[i]);
		strcat(hash, tmp);
    }
}


