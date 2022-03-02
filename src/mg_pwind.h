/*
   ----------------------------------------------------------------------------
   | mg_pwind.so|dll                                                          |
   | Description: Access to DSO functions from YottaDB                        |
   | Author:      Chris Munt cmunt@mgateway.com                               |
   |                         chris.e.munt@gmail.com                           |
   | Copyright (c) 2020-2022 M/Gateway Developments Ltd,                      |
   | Surrey UK.                                                               |
   | All rights reserved.                                                     |
   |                                                                          |
   | http://www.mgateway.com                                                  |
   |                                                                          |
   | Licensed under the Apache License, Version 2.0 (the "License"); you may  |
   | not use this file except in compliance with the License.                 |
   | You may obtain a copy of the License at                                  |
   |                                                                          |
   | http://www.apache.org/licenses/LICENSE-2.0                               |
   |                                                                          |
   | Unless required by applicable law or agreed to in writing, software      |
   | distributed under the License is distributed on an "AS IS" BASIS,        |
   | WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. |
   | See the License for the specific language governing permissions and      |
   | limitations under the License.                                           |      
   |                                                                          |
   ----------------------------------------------------------------------------
*/

#ifndef MG_PWIND_H
#define MG_PWIND_H

#define MGPW_VERSION_MAJOR       "1"
#define MGPW_VERSION_MINOR       "3"
#define MGPW_VERSION_BUILD       "5"

#define MGPW_VERSION             MGPW_VERSION_MAJOR "." MGPW_VERSION_MINOR "." MGPW_VERSION_BUILD

#define WORK_BUFFER              32768


#if defined(_WIN32)

#define BUILDING_NODE_EXTENSION     1
#if defined(_MSC_VER)
/* Check for MS compiler later than VC6 */
#if (_MSC_VER >= 1400)
#define _CRT_SECURE_NO_DEPRECATE    1
#define _CRT_NONSTDC_NO_DEPRECATE   1
#endif
#endif

#elif defined(__linux__) || defined(__linux) || defined(linux)

#if !defined(LINUX)
#define LINUX                       1
#endif

#elif defined(__APPLE__)

#if !defined(MACOSX)
#define MACOSX                      1
#endif

#endif

#if defined(SOLARIS)
#ifndef __GNUC__
#  define  __attribute__(x)
#endif
#endif

#if defined(_WIN32)

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#if defined(__MINGW32__)
#include <math.h>
#endif

#else

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#if defined(SOLARIS)
#include <sys/filio.h>
#endif
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <dlfcn.h>
#include <math.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#endif

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#define MG_DBA_EMBEDDED          1
#include "mg_dbasys.h"
#include "mg_dba.h"


#define MGPW_EXT_NAME            "mg_pwind"
#define MGPW_ERROR_SIZE          512

#ifdef _WIN32
#define MGPW_LOG_FILE            "c:/temp/" MGPW_EXT_NAME ".log"
#else
#define MGPW_LOG_FILE            "/tmp/" MGPW_EXT_NAME ".log"
#endif


#if defined(__linux__) || defined(linux) || defined(LINUX)
#define MGPW_MEMCPY(a,b,c)        memmove(a,b,c)
#else
#define MGPW_MEMCPY(a,b,c)        memcpy(a,b,c)
#endif

typedef void * (* MGPW_MALLOC)   (unsigned long size);
typedef void * (* MGPW_REALLOC)  (void *p, unsigned long size);
typedef int    (* MGPW_FREE)     (void *p);


#if defined(_WIN32)
#define MGPW_EXTFUN(a)           __declspec(dllexport) a __cdecl
#else
#define MGPW_EXTFUN(a)           a
#endif /* #if defined(_WIN32) */


typedef struct tagMGPWLOG {
   char log_file[128];
   char log_level[8];
   short log_errors;
} MGPWLOG, *PMGPWLOG;


#if defined(_WIN32)
typedef DWORD           MGPWTHID;
typedef HINSTANCE       MGPWPLIB;
typedef FARPROC         MGPWPROC;
#else
typedef pthread_t       MGPWTHID;
typedef void            *MGPWPLIB;
typedef void            *MGPWPROC;
#endif


typedef struct tagMGPWMUTEX {
   unsigned char     created;
   int               stack;
#if defined(_WIN32)
   HANDLE            h_mutex;
#else
   pthread_mutex_t   h_mutex;
#endif /* #if defined(_WIN32) */
   MGPWTHID           thid;
} MGPWMUTEX, *PMGPWMUTEX;


#define MGPW_ARG_COUNT(a,b) \
   error_message[0] = '\0'; \
   error_message_len = 0; \
   if (a < b) { \
      strcpy(error_message, "Insufficient arguments supplied to PWIND function"); \
      error_message_len = (int) strlen(error_message); \
      return YDB_FAILURE; \
   } \

#define MGPW_CRYPT_LOAD(a,b) \
   if (b) { \
      a->length = 0; \
      a->address[0] = '\0'; \
   } \
   if (!p_crypt_so->loaded) { \
      if (mgpw_crypt_load_library(p_crypt_so) != YDB_OK) { \
         if (b) { \
            strcpy(a->address, error_message); \
            a->length = (unsigned long) strlen(a->address); \
         } \
         return YDB_FAILURE; \
      } \
   } \

#define MGPW_DB_CONNECTED(a,b) \
   if (!a.buf_addr || !b.address) { \
      strcpy(error_message, "No connection to database"); \
      error_message_len = (int) strlen(error_message); \
      return YDB_FAILURE; \
   } \

#if defined(_WIN32)
#define MGPW_CRYPT_DLL            "libeay32.dll"
#else
#define MGPW_CRYPT_SO             "libcrypto.so"
#define MGPW_CRYPT_SL             "libcrypto.sl"
#define MGPW_CRYPT_DYLIB          "libcrypto.dylib"
#endif

typedef struct tagMGPWCRYPTSO {
   short             loaded;
   char              libnam[256];
   char              dbname[32];
   MGPWPLIB           p_library;

   const char *      (* p_OpenSSL_version)               (int type);
   unsigned char *   (* p_HMAC)                          (const EVP_MD *evp_md, const void *key, int key_len, const unsigned char *d, int n, unsigned char *md, unsigned int *md_len);
   const EVP_MD *    (* p_EVP_sha1)                      (void);
   const EVP_MD *    (* p_EVP_sha256)                    (void);
   const EVP_MD *    (* p_EVP_sha512)                    (void);
   const EVP_MD *    (* p_EVP_md5)                       (void);
   unsigned char *   (* p_SHA1)                          (const unsigned char *d, unsigned long n, unsigned char *md);
   unsigned char *   (* p_SHA256)                        (const unsigned char *d, unsigned long n, unsigned char *md);
   unsigned char *   (* p_SHA512)                        (const unsigned char *d, unsigned long n, unsigned char *md);
   unsigned char *   (* p_MD5)                           (const unsigned char *d, unsigned long n, unsigned char *md);

} MGPWCRYPTSO, *PMGPWCRYPTSO;


#define MGPW_MAX_CLIFD            32
typedef struct tagMGPWTCPSRV {
   int count;
   int port;
   int srv_sockfd;
   int cli_sockfd;
   int new_sockfd[MGPW_MAX_CLIFD];
   struct sockaddr_in srv_addr;
   struct sockaddr_in cli_addr;

#if !defined(_WIN32)
   pthread_t stdout_tid;
   pthread_t domsrv_tid;
#endif
   char domsrv_name[256];
   int domsrv_sockfd;
   int domcli_sockfd;
#if !defined(_WIN32)
   struct sockaddr_un domsrv_addr;
   struct sockaddr_un domcli_addr;
#endif

   unsigned int wbuffer_size;
   unsigned int wbuffer_datasize;
   unsigned int wbuffer_offset;
   unsigned char wbuffer[WORK_BUFFER];
} MGPWTCPSRV, *PMGPWTCPSRV;


/* CRC32 */

#define UPDC32(octet,crc) (crc_32_tab[((crc) ^ ((unsigned char) octet)) & 0xff] ^ ((crc) >> 8))

static unsigned long crc_32_tab[] = { /* CRC polynomial 0xedb88320 */
0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};


#if defined(_WIN32)
extern CRITICAL_SECTION mgpw_global_mutex;
#else
extern pthread_mutex_t  mgpw_global_mutex;
#endif

extern MGPW_MALLOC      mgpw_ext_malloc;
extern MGPW_REALLOC     mgpw_ext_realloc;
extern MGPW_FREE        mgpw_ext_free;

MGPW_EXTFUN(int)        mg_version                    (int count, ydb_string_t *out);
MGPW_EXTFUN(int)        mg_error                      (int count, ydb_string_t *error);
MGPW_EXTFUN(int)        mg_crypt_library              (int count, ydb_string_t *in);
MGPW_EXTFUN(int)        mg_ssl_version                (int count, ydb_string_t *out, ydb_string_t *error);
MGPW_EXTFUN(int)        mg_sha1                       (int count, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error);
MGPW_EXTFUN(int)        mg_sha256                     (int count, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error);
MGPW_EXTFUN(int)        mg_sha512                     (int count, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error);
MGPW_EXTFUN(int)        mg_md5                        (int count, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error);

MGPW_EXTFUN(int)        mg_hmac_sha1                  (int count, ydb_string_t *key, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error);
MGPW_EXTFUN(int)        mg_hmac_sha256                (int count, ydb_string_t *key, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error);
MGPW_EXTFUN(int)        mg_hmac_sha512                (int count, ydb_string_t *key, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error);
MGPW_EXTFUN(int)        mg_hmac_md5                   (int count, ydb_string_t *key, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error);

MGPW_EXTFUN(int)        mg_encode_b64                 (int count, ydb_string_t *in, ydb_string_t *out);
MGPW_EXTFUN(int)        mg_decode_b64                 (int count, ydb_string_t *in, ydb_string_t *out);
MGPW_EXTFUN(int)        mg_crc32                      (int count, ydb_string_t *in, ydb_uint_t *out);

MGPW_EXTFUN(int)        mg_dbopen                     (int count, ydb_string_t *dbtype, ydb_string_t *path, ydb_string_t *host, ydb_string_t *port, ydb_string_t *username, ydb_string_t *password, ydb_string_t *nspace, ydb_string_t *parameters);
MGPW_EXTFUN(int)        mg_dbclose                    (int count);
MGPW_EXTFUN(int)        mg_dbget                      (int count, ydb_string_t *out, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10);
MGPW_EXTFUN(int)        mg_dbset                      (int count, ydb_string_t *data, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10);
MGPW_EXTFUN(int)        mg_dbkill                     (int count, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10);
MGPW_EXTFUN(int)        mg_dborder                    (int count, ydb_string_t *key, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10);
MGPW_EXTFUN(int)        mg_dborderdata                (int count, ydb_string_t *key, ydb_string_t *data, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10);
MGPW_EXTFUN(int)        mg_dbprevious                 (int count, ydb_string_t *key, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10);
MGPW_EXTFUN(int)        mg_dbpreviousdata             (int count, ydb_string_t *key, ydb_string_t *data, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10);
MGPW_EXTFUN(int)        mg_dbincrement                (int count, ydb_string_t *data, ydb_string_t *increment, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10);
MGPW_EXTFUN(int)        mg_dblock                     (int count, ydb_string_t *result, ydb_string_t *timeout, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10);
MGPW_EXTFUN(int)        mg_dbunlock                   (int count, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10);
MGPW_EXTFUN(int)        mg_dbtstart                   (int count);
MGPW_EXTFUN(int)        mg_dbtlevel                   (int count, ydb_string_t *data);
MGPW_EXTFUN(int)        mg_dbtcommit                  (int count);
MGPW_EXTFUN(int)        mg_dbtrollback                (int count);
MGPW_EXTFUN(int)        mg_dbfunction                 (int count, ydb_string_t *data, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10);
MGPW_EXTFUN(int)        mg_dbclassmethod              (int count, ydb_string_t *data, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10);
MGPW_EXTFUN(int)        mg_dbgetproperty              (int count, ydb_string_t *data, ydb_string_t *oref, ydb_string_t *pname);
MGPW_EXTFUN(int)        mg_dbsetproperty              (int count, ydb_string_t *data, ydb_string_t *oref, ydb_string_t *pname);
MGPW_EXTFUN(int)        mg_dbmethod                   (int count, ydb_string_t *data, ydb_string_t *oref, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10);
MGPW_EXTFUN(int)        mg_dbcloseinstance            (int count, ydb_string_t *oref);

#if !defined(_WIN32)
MGPW_EXTFUN(int)        mg_tcp_options                (int count, ydb_string_t *options, ydb_string_t *error);
MGPW_EXTFUN(int)        mg_tcpserver_init             (int count, ydb_int_t port, ydb_string_t *options, ydb_string_t *error);
MGPW_EXTFUN(int)        mg_tcpserver_accept           (int count, ydb_string_t *key, ydb_string_t *error);
MGPW_EXTFUN(int)        mg_tcpserver_close            (int count, ydb_string_t *key);
MGPW_EXTFUN(int)        mg_tcpchild_init              (int count, ydb_string_t *key, ydb_string_t *options, ydb_string_t *error);
MGPW_EXTFUN(int)        mg_tcpchild_send              (int count, ydb_string_t *data, ydb_int_t flush, ydb_string_t *error);
MGPW_EXTFUN(int)        mg_tcpchild_recv              (int count, ydb_string_t *data, ydb_int_t len, ydb_int_t timeout, ydb_string_t *error);
MGPW_EXTFUN(int)        mg_tcpchild_recv_ascii        (int count, ydb_int_t *data, ydb_int_t timeout, ydb_string_t *error);
MGPW_EXTFUN(int)        mg_tcpchild_recv_message      (int count, ydb_string_t *data, ydb_int_t *len, ydb_int_t *cmnd, ydb_int_t timeout, ydb_string_t *error);
MGPW_EXTFUN(int)        mg_tcpchild_close             (int count);
#endif

int                     mgpw_crypt_load_library       (MGPWCRYPTSO *p_crypt_so);

int                     mgpw_pack_args                (DBXSTR *pblock, int count, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10);
int                     mgpw_unpack_result            (DBXSTR *pblock, ydb_string_t *out);
int                     mgpw_unpack_result2           (DBXSTR *pblock, ydb_string_t *out1, ydb_string_t *out2);

int                     mgpw_set_size                 (unsigned char *str, unsigned long data_len);
unsigned long           mgpw_get_size                 (unsigned char *str);

void *                  mgpw_realloc                  (void *p, int curr_size, int new_size, short id);
void *                  mgpw_malloc                   (int size, short id);
int                     mgpw_free                     (void *p, short id);

int                     mgpw_lcase                    (char *string);
int                     mgpw_log_init                 (MGPWLOG *p_log);
int                     mgpw_log_event                (MGPWLOG *p_log, char *message, char *title, int level);
int                     mgpw_log_buffer               (MGPWLOG *p_log, char *buffer, int buffer_len, char *title, int level);
MGPWPLIB                mgpw_dso_load                 (char *library);
MGPWPROC                mgpw_dso_sym                  (MGPWPLIB p_library, char *symbol);
int                     mgpw_dso_unload               (MGPWPLIB p_library);
MGPWTHID                mgpw_current_thread_id        (void);
unsigned long           mgpw_current_process_id       (void);

int                     mgpw_mutex_create             (MGPWMUTEX *p_mutex);
int                     mgpw_mutex_lock               (MGPWMUTEX *p_mutex, int timeout);
int                     mgpw_mutex_unlock             (MGPWMUTEX *p_mutex);
int                     mgpw_mutex_destroy            (MGPWMUTEX *p_mutex);
int                     mgpw_init_critical_section    (void *p_crit);
int                     mgpw_delete_critical_section  (void *p_crit);
int                     mgpw_enter_critical_section   (void *p_crit);
int                     mgpw_leave_critical_section   (void *p_crit);
int                     mgpw_sleep                    (unsigned long msecs);

char                    mgpw_b64_ntc                  (unsigned char n);
unsigned char           mgpw_b64_ctn                  (char c);
int                     mgpw_b64_encode               (char *from, int length, char *to, int quads);
int                     mgpw_b64_decode               (char *from, int length, char *to);
int                     mgpw_b64_enc_buffer_size      (int l, int q);
int                     mgpw_b64_strip_enc_buffer     (char *buf, int length);
int                     mgpw_hex_encode               (char *from, int length, char *to);
unsigned long           mgpw_crc32_checksum           (char *buffer, size_t len);

#if !defined(_WIN32)
void *                  mgpw_stdin_listener           (void *pargs);
void *                  mgpw_stdout_listener          (void *pargs);
void *                  mgpw_domsrv_listener          (void *pargs);
int                     mgpw_domsrv_init              ();
int                     mgpw_domsrv_sendfd            (int sockfd);
int                     mgpw_domsrv_recvfd            (char *key, char *options, char *error);
int                     mgpw_tcpsrv_init              (int port, char *options, char *error);
int                     mgpw_tcpsrv_accept            (char *key, char *error);
int                     mgpw_tcpsrv_send              (char *data, int len, int flush, char *error);
int                     mgpw_tcpsrv_recv              (char *data, int dsize, int len, int timeout, char *error);
int                     mgpw_tcpsrv_recv_message      (char *data, int dsize, int *len, int *cmnd, int timeout, char *error);
int                     mgpw_tcpsrv_close             (char *key);
#endif

#endif

