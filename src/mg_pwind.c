/*
   ----------------------------------------------------------------------------
   | mg_pwind.so|dll                                                          |
   | Description: Access to DSO functions from YottaDB                        |
   | Author:      Chris Munt cmunt@mgateway.com                               |
   |                         chris.e.munt@gmail.com                           |
   | Copyright (c) 2019-2023 MGateway Ltd                                     |
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

/*
   Development Diary (in brief):

Version 1.0.1 5 March 2021:
   First release.

Version 1.2.2 23 March 2021:
   Introduce experimental network I/O layer.

Version 1.3.3 15 February 2022:
   Introduce experimental access to InterSystems databases.

Version 1.3.4 18 February 2022:
   Introduce experimental access to InterSystems classes.

Version 1.3.5 1 March 2022:
   Add an interface for the InterSystems Global Lock command.
   Add an interface to gracefully close InterSystems Object References (orefs).
   Add interfaces to get the data as well as the next (or previous) key values for InterSystems databases.

Version 1.3.6 17 March 2022:
   Introduce support for long strings through the mg_pwind interface.
	- Maximum string length for YottaDB: 1,048,576 Bytes.
	- Maximum string length for InterSystems databases: 3,641,144 Bytes (32,767 Bytes for older systems).
   Introduce a simple wait/signal mechanism to aid communication between YottaDB processes.
   - pwind.signalwait() and pwind.signal().

Version 1.3.7 8 April 2022:
   Introduce a scheme for dealing with large strings from InterSystems IRIS and Cache.
	- Maximum string length for InterSystems DB Servers is usually 3,641,144 Bytes whereas for YottaDB it is currently 1,048,576 Bytes.

Version 1.3.7a 23 June 2023:
   Documentation update.

*/

#include "mg_pwind.h"

#if !defined(_WIN32)
extern int errno;
#endif

static MGPWCRYPTSO   crypt_so             = {0, {0}, {0}, NULL, NULL};
static MGPWCRYPTSO   *p_crypt_so          = &crypt_so;

static MGPWTCPSRV    tcpsrv               = {0, 0};
static MGPWTCPSRV    *p_tcpsrv            = &tcpsrv;

static MGPWLOG        pwindlog            = {"/tmp/mg_pwind.log", {0}, 0};
static MGPWLOG       *p_log               = &pwindlog;

static char          error_message[512]   = {0};
static int           error_message_len    = 0;
static int           error_code           = 0;
static DBXSTR        gblock               = {0, 0, NULL};
static ydb_string_t  gresult              = {0, NULL};
static unsigned long gresult_size         = 256;
static int           isc_net_connection   = 0;
#define OUTPUT_STRING_IDX                 15
static MGPWSSTACK    string_stack[16]     = {{0, 0, 0, 0, 0, 0, {0, NULL}},
                                             {0, 0, 0, 0, 0, 0, {0, NULL}},
                                             {0, 0, 0, 0, 0, 0, {0, NULL}},
                                             {0, 0, 0, 0, 0, 0, {0, NULL}},
                                             {0, 0, 0, 0, 0, 0, {0, NULL}},
                                             {0, 0, 0, 0, 0, 0, {0, NULL}},
                                             {0, 0, 0, 0, 0, 0, {0, NULL}},
                                             {0, 0, 0, 0, 0, 0, {0, NULL}},
                                             {0, 0, 0, 0, 0, 0, {0, NULL}},
                                             {0, 0, 0, 0, 0, 0, {0, NULL}},
                                             {0, 0, 0, 0, 0, 0, {0, NULL}},
                                             {0, 0, 0, 0, 0, 0, {0, NULL}},
                                             {0, 0, 0, 0, 0, 0, {0, NULL}},
                                             {0, 0, 0, 0, 0, 0, {0, NULL}},
                                             {0, 0, 0, 0, 0, 0, {0, NULL}},
                                             {0, 0, 0, 0, 0, 0, {0, NULL}}
                                            };

#if defined(_WIN32)
CRITICAL_SECTION     mgpw_global_mutex;
#else
pthread_mutex_t      mgpw_global_mutex    = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t      mgpw_cond_mutex      = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t       mgpw_cond            = PTHREAD_COND_INITIALIZER;
static int           mgpw_cond_flag       = 0;
static int           mgpw_pipe_status     = 0;
static int           mgpw_pipefd[2]       = {0, 0};
#endif


#if defined(_WIN32)
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
   switch (fdwReason)
   { 
      case DLL_PROCESS_ATTACH:
         mgpw_init_critical_section((void *) &mgpw_global_mutex);
         break;
      case DLL_THREAD_ATTACH:
         break;
      case DLL_THREAD_DETACH:
         break;
      case DLL_PROCESS_DETACH:
         mgpw_delete_critical_section((void *) &mgpw_global_mutex);
         break;
   }
   return TRUE;
}
#endif /* #if defined(_WIN32) */


MGPW_EXTFUN(int) mg_version(int count, ydb_string_t *out)
{
   MGPW_ARG_COUNT(count, 1);

   sprintf((char *) out->address, "mg_pwind:%s", MGPW_VERSION);
   out->length = (int) strlen(out->address);

   return YDB_OK;
}


MGPW_EXTFUN(int) mg_error(int count, ydb_string_t *error)
{
   if (count < 1) {
      return YDB_OK;
   }

   error->address[0] = '\0';
   error->length = 0;

   if (error_message_len == 0) {
      error_message_len = (int) strlen(error_message);
   }
   memcpy((void *) error->address, (void *) error_message, (size_t) error_message_len);
   error->length = (unsigned long) error_message_len;
   return YDB_OK;
}


MGPW_EXTFUN(int) mg_crypt_library(int count, ydb_string_t *in)
{
   MGPW_ARG_COUNT(count, 1);

   strcpy(p_crypt_so->libnam, in->address);

   return YDB_OK;
}


MGPW_EXTFUN(int) mg_ssl_version(int count, ydb_string_t *out, ydb_string_t *error)
{
   MGPW_ARG_COUNT(count, 1);
   out->address[0] = '\0';
   out->length = 0;
   MGPW_CRYPT_LOAD(error, (count == 2));

   strcpy((char *) out->address, p_crypt_so->p_OpenSSL_version(0));
   out->length = (int) strlen(out->address);

   return YDB_OK;
}


MGPW_EXTFUN(int) mg_sha1(int count, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error)
{
   int mac_len, len;
   char mac[1024];

   MGPW_ARG_COUNT(count, 3);
   out->address[0] = '\0';
   out->length = 0;
   MGPW_CRYPT_LOAD(error, (count == 4));

   memset(mac, 0, 1024);
   p_crypt_so->p_SHA1(in->address, in->length, mac);
   mac_len = 20;

   if (flags == 1) {
      len = mgpw_b64_encode((char *) mac, mac_len, out->address, 0);
      out->address[len] = '\0';
      out->length = len;
   }
   else if (flags == 2) {
      len = mgpw_hex_encode((char *) mac, mac_len, out->address);
      out->address[len] = '\0';
      out->length = len;
   }
   else {
      memcpy((void *) out->address, (void *) mac, (size_t) mac_len);
      out->length = mac_len;
   }

   return YDB_OK;
}


MGPW_EXTFUN(int) mg_sha256(int count, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error)
{
   int mac_len, len;
   char mac[1024];

   MGPW_ARG_COUNT(count, 3);
   out->address[0] = '\0';
   out->length = 0;
   MGPW_CRYPT_LOAD(error, (count == 4));

   memset(mac, 0, 1024);
   p_crypt_so->p_SHA256(in->address, in->length, mac);
   mac_len = 32;

   if (flags == 1) {
      len = mgpw_b64_encode((char *) mac, mac_len, out->address, 0);
      out->address[len] = '\0';
      out->length = len;
   }
   else if (flags == 2) {
      len = mgpw_hex_encode((char *) mac, mac_len, out->address);
      out->address[len] = '\0';
      out->length = len;
   }
   else {
      memcpy((void *) out->address, (void *) mac, (size_t) mac_len);
      out->length = mac_len;
   }

   return YDB_OK;
}


MGPW_EXTFUN(int) mg_sha512(int count, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error)
{
   int mac_len, len;
   char mac[1024];

   MGPW_ARG_COUNT(count, 3);
   out->address[0] = '\0';
   out->length = 0;
   MGPW_CRYPT_LOAD(error, (count == 4));

   memset(mac, 0, 1024);
   p_crypt_so->p_SHA512(in->address, in->length, mac);
   mac_len = 64;

   if (flags == 1) {
      len = mgpw_b64_encode((char *) mac, mac_len, out->address, 0);
      out->address[len] = '\0';
      out->length = len;
   }
   else if (flags == 2) {
      len = mgpw_hex_encode((char *) mac, mac_len, out->address);
      out->address[len] = '\0';
      out->length = len;
   }
   else {
      memcpy((void *) out->address, (void *) mac, (size_t) mac_len);
      out->length = mac_len;
   }

   return YDB_OK;
}


MGPW_EXTFUN(int) mg_md5(int count, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error)
{
   int mac_len, len;
   char mac[1024];

   MGPW_ARG_COUNT(count, 3);
   out->address[0] = '\0';
   out->length = 0;
   MGPW_CRYPT_LOAD(error, (count == 4));

   memset(mac, 0, 1024);
   p_crypt_so->p_MD5(in->address, in->length, mac);
   mac_len = 16;

   if (flags == 1) {
      len = mgpw_b64_encode((char *) mac, mac_len, out->address, 0);
      out->address[len] = '\0';
      out->length = len;
   }
   else if (flags == 2) {
      len = mgpw_hex_encode((char *) mac, mac_len, out->address);
      out->address[len] = '\0';
      out->length = len;
   }
   else {
      memcpy((void *) out->address, (void *) mac, (size_t) mac_len);
      out->length = mac_len;
   }

   return YDB_OK;
}


MGPW_EXTFUN(int) mg_hmac_sha1(int count, ydb_string_t *key, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error)
{
   int mac_len, len;
   char mac[1024];

   MGPW_ARG_COUNT(count, 4);
   out->address[0] = '\0';
   out->length = 0;
   MGPW_CRYPT_LOAD(error, (count == 5));

   memset(mac, 0, 1024);
   p_crypt_so->p_HMAC(p_crypt_so->p_EVP_sha1(), key->address, key->length, in->address, in->length, mac, &mac_len);

   if (flags == 1) {
      len = mgpw_b64_encode((char *) mac, mac_len, out->address, 0);
      out->address[len] = '\0';
      out->length = len;
   }
   else if (flags == 2) {
      len = mgpw_hex_encode((char *) mac, mac_len, out->address);
      out->address[len] = '\0';
      out->length = len;
   }
   else {
      memcpy((void *) out->address, (void *) mac, (size_t) mac_len);
      out->length = mac_len;
   }

   return YDB_OK;
}


MGPW_EXTFUN(int) mg_hmac_sha256(int count, ydb_string_t *key, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error)
{
   int mac_len, len;
   char mac[1024];

   MGPW_ARG_COUNT(count, 4);
   out->address[0] = '\0';
   out->length = 0;
   MGPW_CRYPT_LOAD(error, (count == 5));

   memset(mac, 0, 1024);
   p_crypt_so->p_HMAC(p_crypt_so->p_EVP_sha256(), key->address, key->length, in->address, in->length, mac, &mac_len);

   if (flags == 1) {
      len = mgpw_b64_encode((char *) mac, mac_len, out->address, 0);
      out->address[len] = '\0';
      out->length = len;
   }
   else if (flags == 2) {
      len = mgpw_hex_encode((char *) mac, mac_len, out->address);
      out->address[len] = '\0';
      out->length = len;
   }
   else {
      memcpy((void *) out->address, (void *) mac, (size_t) mac_len);
      out->length = mac_len;
   }

   return YDB_OK;
}


MGPW_EXTFUN(int) mg_hmac_sha512(int count, ydb_string_t *key, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error)
{
   int mac_len, len;
   char mac[1024];

   MGPW_ARG_COUNT(count, 4);
   out->address[0] = '\0';
   out->length = 0;
   MGPW_CRYPT_LOAD(error, (count == 5));

   memset(mac, 0, 1024);
   p_crypt_so->p_HMAC(p_crypt_so->p_EVP_sha512(), key->address, key->length, in->address, in->length, mac, &mac_len);

   if (flags == 1) {
      len = mgpw_b64_encode((char *) mac, mac_len, out->address, 0);
      out->address[len] = '\0';
      out->length = len;
   }
   else if (flags == 2) {
      len = mgpw_hex_encode((char *) mac, mac_len, out->address);
      out->address[len] = '\0';
      out->length = len;
   }
   else {
      memcpy((void *) out->address, (void *) mac, (size_t) mac_len);
      out->length = mac_len;
   }

   return YDB_OK;
}


MGPW_EXTFUN(int) mg_hmac_md5(int count, ydb_string_t *key, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error)
{
   int mac_len, len;
   char mac[1024];

   MGPW_ARG_COUNT(count, 4);
   out->address[0] = '\0';
   out->length = 0;
   MGPW_CRYPT_LOAD(error, (count == 5));

   memset(mac, 0, 1024);
   p_crypt_so->p_HMAC(p_crypt_so->p_EVP_md5(), key->address, key->length, in->address, in->length, mac, &mac_len);

   if (flags == 1) {
      len = mgpw_b64_encode((char *) mac, mac_len, out->address, 0);
      out->address[len] = '\0';
      out->length = len;
   }
   else if (flags == 2) {
      len = mgpw_hex_encode((char *) mac, mac_len, out->address);
      out->address[len] = '\0';
      out->length = len;
   }
   else {
      memcpy((void *) out->address, (void *) mac, (size_t) mac_len);
      out->length = mac_len;
   }

   return YDB_OK;
}


MGPW_EXTFUN(int) mg_encode_b64(int count, ydb_string_t *in, ydb_string_t *out)
{
   int len;

   MGPW_ARG_COUNT(count, 2);
   out->address[0] = '\0';
   out->length = 0;

   len = mgpw_b64_encode((char *) in->address, in->length, out->address, 0);
   out->address[len] = '\0';
   out->length = len;

   return YDB_OK;
}


MGPW_EXTFUN(int) mg_decode_b64(int count, ydb_string_t *in, ydb_string_t *out)
{
   int len;

   MGPW_ARG_COUNT(count, 2);
   out->address[0] = '\0';
   out->length = 0;

   len = mgpw_b64_decode((char *) in->address, in->length, out->address);
   out->address[len] = '\0';
   out->length = len;

   return YDB_OK;
}


MGPW_EXTFUN(int) mg_crc32(int count, ydb_string_t *in, ydb_uint_t *out)
{
   MGPW_ARG_COUNT(count, 2);

   *out = (ydb_uint_t) mgpw_crc32_checksum(in->address, (size_t) in->length);

   return YDB_OK;
}


/* v1.3.6 */
void mg_signalwait_handler(int sig)
{
#if !defined(_WIN32)
   int rc, errno_orig;

   if (mgpw_pipe_status) {
      errno_orig = errno;
      rc = write(mgpw_pipefd[1], "x", 1);
      errno = errno_orig;
   }
   return;
#else
   return;
#endif
}


MGPW_EXTFUN(int) mg_signalwait(int count, ydb_uint_t *result, ydb_int_t timeout)
{
#if !defined(_WIN32)
   int rc, ready, nfds, flags;
   struct timeval to, *pto;
   fd_set read_set;
   struct sigaction sa, oldusr1;
   char ch;
   int fd, j;

   /* The classic self-pipe trick */

   *result = 1;
   nfds = 0;
   pto = NULL;
   if (timeout != -1) {
      to.tv_sec = 0;
      to.tv_usec = (timeout * 1000);
      pto = &to;
   }


   if (mgpw_pipe_status == 0) {
      rc = pipe(mgpw_pipefd);
      if (rc == -1) {
         *result = -1;
         return YDB_OK;
      }
      flags = fcntl(mgpw_pipefd[0], F_GETFL);
      if (flags == -1) {
         *result = -1;
         return YDB_OK;
      }
      flags |= O_NONBLOCK;
      if (fcntl(mgpw_pipefd[0], F_SETFL, flags) == -1) {
         *result = -1;
         return YDB_OK;
      }

      flags = fcntl(mgpw_pipefd[1], F_GETFL);
      if (flags == -1) {
         *result = -1;
         return YDB_OK;
      }
      flags |= O_NONBLOCK;
      if (fcntl(mgpw_pipefd[1], F_SETFL, flags) == -1) {
         *result = -1;
         return YDB_OK;
      }
      mgpw_pipe_status = 1;
   }

   FD_ZERO(&read_set);
   FD_SET(mgpw_pipefd[0], &read_set);
   nfds = mgpw_pipefd[0] + 1;

   sigemptyset(&sa.sa_mask);
   sa.sa_flags = SA_RESTART;
   sa.sa_handler = mg_signalwait_handler;
/*
   if (sigaction(SIGINT, &sa, NULL) == -1) {
      *result = -1;
      return YDB_OK;
   }
*/
   sigaction(SIGUSR1, NULL, &oldusr1);

   if (sigaction(SIGUSR1, &sa, NULL) == -1) {
      sigaction(SIGUSR1, &oldusr1, NULL);
      *result = -1;
      return YDB_OK;
   }
/*
   if (sigaction(SIGUSR2, &sa, NULL) == -1) {
      *result = -1;
      return YDB_OK;
   }
*/

   rc = read(mgpw_pipefd[0], &ch, 1);
   if (rc == 1 && ch == 'x') {
      return YDB_OK;
   }

   while (1) {
      rc = select(nfds, &read_set, NULL, NULL, pto);
      if (rc == -1 && errno == EINTR)  {
         continue;
      }
      if (rc == -1) {
         *result = -1;
         break;
      }
      if (rc == 0) {
         *result = 0;
         break;
      }
      if (FD_ISSET(mgpw_pipefd[0], &read_set)) {
         rc = read(mgpw_pipefd[0], &ch, 1);
         break;
      }
   }
/*
   while (1) {
      rc = read(mgpw_pipefd[0], &ch, 1);
      if (rc == -1 && errno == EAGAIN) {
         break;
      }
   }
*/
   sigaction(SIGUSR1, &oldusr1, NULL);

   return YDB_OK;
#else
   return YDB_OK;
#endif
}


MGPW_EXTFUN(int) mg_signal(int count, ydb_ulong_t pid)
{
#if !defined(_WIN32)
   int rc;

   rc = kill((pid_t) pid, SIGUSR1);

   return YDB_OK;
#else
   return YDB_OK;
#endif
}


/* v1.3.3 */
MGPW_EXTFUN(int) mg_dbopen(int count, ydb_string_t *dbtype, ydb_string_t *path, ydb_string_t *host, ydb_string_t *port, ydb_string_t *username, ydb_string_t *password, ydb_string_t *nspace, ydb_string_t *parameters)
{
   int n, rc;
   DBXSTR *pblock;
   ydb_string_t *presult;
#if !defined(_WIN32)
   struct sigaction oldact;
#endif

   MGPW_ARG_COUNT(count, 7);

   if (!gblock.buf_addr) {
      gblock.buf_addr = (char *) mg_malloc(DBX_YDB_BUFFER + 10, 0);
      if (!gblock.buf_addr) {
         return YDB_FAILURE;
      }
      gblock.len_alloc = (DBX_YDB_BUFFER + 10);
      gblock.len_used = 0;
   }
   if (!gresult.address) {
      gresult.address = (char *) mg_malloc(gresult_size, 0);
      if (!gresult.address) {
         return YDB_FAILURE;
      }
      gresult.length = gresult_size;
   }

   pblock = &gblock;
   pblock->len_used = 0;
   presult = &gresult;
   presult->length = gresult_size;

   dbx_init();

   mg_add_block_head(pblock, (unsigned long) pblock->len_alloc, (unsigned long) 0);
   for (n = 0; n < 14; n ++) {
      if (n < count) {
         if (n == 0)
            mg_add_block_data(pblock, (unsigned char *) dbtype->address, (unsigned long) dbtype->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
         else if (n == 1)
            mg_add_block_data(pblock, (unsigned char *) path->address, (unsigned long) path->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
         else if (n == 2)
            mg_add_block_data(pblock, (unsigned char *) host->address, (unsigned long) host->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
         else if (n == 3)
            mg_add_block_data(pblock, (unsigned char *) port->address, (unsigned long) port->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
         else if (n == 4)
            mg_add_block_data(pblock, (unsigned char *) username->address, (unsigned long) username->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
         else if (n == 5)
            mg_add_block_data(pblock, (unsigned char *) password->address, (unsigned long) password->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
         else if (n == 6)
            mg_add_block_data(pblock, (unsigned char *) nspace->address, (unsigned long) nspace->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
         else
            mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_DATA, DBX_DTYPE_STR);
      }
      else {
         mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_DATA, DBX_DTYPE_STR);
      }
   }
   mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_EOD, DBX_DTYPE_STR);
   mg_add_block_head_size(pblock, pblock->len_used, DBX_CMND_OPEN);

   isc_net_connection = 0;
   if (path->length == 0 && host->length > 0 && port->length > 0) {
      isc_net_connection = 1;
   }

#if !defined(_WIN32)
   sigaction(SIGALRM, NULL, &oldact);
#endif

   rc = dbx_open((unsigned char *) pblock->buf_addr, NULL);
   memcpy(error_message, pblock->buf_addr, pblock->len_used);
   error_message_len = pblock->len_used;

#if !defined(_WIN32)
   sigaction(SIGALRM, &oldact, NULL);
#endif
   rc = mgpw_unpack_result(pblock, presult, 0);

   return rc;
}


MGPW_EXTFUN(int) mg_dbclose(int count)
{
   int rc;
   DBXSTR *pblock;
   ydb_string_t *presult;

   if (!gblock.buf_addr || !gresult.address) {
      return YDB_FAILURE;
   }
   pblock = &gblock;
   pblock->len_used = 0;
   presult = &gresult;
   presult->length = gresult_size;

   mg_add_block_head(pblock, (unsigned long) pblock->len_alloc, (unsigned long) 0);
   mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_EOD, DBX_DTYPE_STR);
   mg_add_block_head_size(pblock, pblock->len_used, DBX_CMND_CLOSE);

   rc = dbx_close((unsigned char *) pblock->buf_addr, NULL);

   rc = mgpw_unpack_result(pblock, presult, 0);

   return rc;
}


MGPW_EXTFUN(int) mg_dbget(int count, ydb_string_t *data, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10)
{
   int rc;
   DBXSTR *pblock;
   DBXMETH *pmeth;

   MGPW_ARG_COUNT(count, 2);
   MGPW_DB_CONNECTED(gblock, gresult);
   mgpw_prereq_buffers();

   pblock = &gblock;
   pblock->len_used = 0;

   mg_add_block_head(pblock, (unsigned long) pblock->len_alloc, (unsigned long) 0);
   mgpw_pack_args(pblock, count - 1, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10);
   mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_EOD, DBX_DTYPE_STR);
   mg_add_block_head_size(pblock, pblock->len_used, DBX_CMND_GGET);

   pmeth = mg_unpack_header((unsigned char *) pblock->buf_addr, NULL);
   pmeth->output_val.realloc = 2;
   rc = dbx_get_x(pmeth);

   rc = mgpw_unpack_result(&(pmeth->output_val.svalue), data, 1);
   mgpw_postreq_buffers(pmeth, pblock);

   return rc;
}


MGPW_EXTFUN(int) mg_dbset(int count, ydb_string_t *data, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10)
{
   int rc;
   DBXSTR *pblock;
   DBXMETH *pmeth;
   ydb_string_t *presult;

   MGPW_ARG_COUNT(count, 2);
   MGPW_DB_CONNECTED(gblock, gresult);
   mgpw_prereq_buffers();

   pblock = &gblock;
   pblock->len_used = 0;
   presult = &gresult;
   presult->length = gresult_size;

   mg_add_block_head(pblock, (unsigned long) pblock->len_alloc, (unsigned long) 0);
   mgpw_pack_args(pblock, count - 1, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10);
   mg_add_block_data_ex(pblock, 0, (unsigned char *) data->address, (unsigned long) data->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
   mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_EOD, DBX_DTYPE_STR);
   mg_add_block_head_size(pblock, pblock->len_used, DBX_CMND_GSET);
   pmeth = mg_unpack_header((unsigned char *) pblock->buf_addr, NULL);

   pmeth->output_val.realloc = 2;
   rc = dbx_set_x(pmeth);

   rc = mgpw_unpack_result(&(pmeth->output_val.svalue), presult, 0);
   mgpw_postreq_buffers(pmeth, pblock);

   return rc;
}


MGPW_EXTFUN(int) mg_dbkill(int count, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10)
{
   int rc;
   DBXSTR *pblock;
   DBXMETH *pmeth;
   ydb_string_t *presult;

   MGPW_ARG_COUNT(count, 1);
   MGPW_DB_CONNECTED(gblock, gresult);
   mgpw_prereq_buffers();

   pblock = &gblock;
   pblock->len_used = 0;
   presult = &gresult;
   presult->length = gresult_size;

   mg_add_block_head(pblock, (unsigned long) pblock->len_alloc, (unsigned long) 0);
   mgpw_pack_args(pblock, count, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10);
   mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_EOD, DBX_DTYPE_STR);
   mg_add_block_head_size(pblock, pblock->len_used, DBX_CMND_GDELETE);

   pmeth = mg_unpack_header((unsigned char *) pblock->buf_addr, NULL);
   pmeth->output_val.realloc = 2;
   rc = dbx_delete_x(pmeth);

   rc = mgpw_unpack_result(&(pmeth->output_val.svalue), presult, 0);
   mgpw_postreq_buffers(pmeth, pblock);

   return rc;
}


MGPW_EXTFUN(int) mg_dborder(int count, ydb_string_t *key, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10)
{
   int rc;
   DBXSTR *pblock;
   DBXMETH *pmeth;

   MGPW_ARG_COUNT(count, 3);
   MGPW_DB_CONNECTED(gblock, gresult);
   mgpw_prereq_buffers();

   pblock = &gblock;
   pblock->len_used = 0;
   mg_add_block_head(pblock, (unsigned long) pblock->len_alloc, (unsigned long) 0);
   mgpw_pack_args(pblock, count - 1, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10);
   mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_EOD, DBX_DTYPE_STR);
   mg_add_block_head_size(pblock, pblock->len_used, DBX_CMND_GNEXT);

   pmeth = mg_unpack_header((unsigned char *) pblock->buf_addr, NULL);
   pmeth->output_val.realloc = 2;
   rc = dbx_next_x(pmeth);

   rc = mgpw_unpack_result(&(pmeth->output_val.svalue), key, 1);
   mgpw_postreq_buffers(pmeth, pblock);

   return rc;
}


MGPW_EXTFUN(int) mg_dborderdata(int count, ydb_string_t *key, ydb_string_t *data, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10)
{
   int rc;
   DBXSTR *pblock;
   DBXMETH *pmeth;

   MGPW_ARG_COUNT(count, 3);
   MGPW_DB_CONNECTED(gblock, gresult);
   mgpw_prereq_buffers();

   pblock = &gblock;
   pblock->len_used = 0;
   mg_add_block_head(pblock, (unsigned long) pblock->len_alloc, (unsigned long) 0);
   mgpw_pack_args(pblock, count - 2, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10);
   mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_EOD, DBX_DTYPE_STR);
   mg_add_block_head_size(pblock, pblock->len_used, DBX_CMND_GNEXTDATA);

   pmeth = mg_unpack_header((unsigned char *) pblock->buf_addr, NULL);
   pmeth->output_val.realloc = 2;
   rc = dbx_next_data_x(pmeth);

   if (isc_net_connection)
      rc = mgpw_unpack_result2(&(pmeth->output_val.svalue), key, data, 1, 0);
   else
      rc = mgpw_unpack_result2(&(pmeth->output_val.svalue), data, key, 1, 1);

   mgpw_postreq_buffers(pmeth, pblock);

   return rc;
}


MGPW_EXTFUN(int) mg_dbprevious(int count, ydb_string_t *key, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10)
{
   int rc;
   DBXSTR *pblock;
   DBXMETH *pmeth;

   MGPW_ARG_COUNT(count, 3);
   MGPW_DB_CONNECTED(gblock, gresult);
   mgpw_prereq_buffers();

   pblock = &gblock;
   pblock->len_used = 0;
   mg_add_block_head(pblock, (unsigned long) pblock->len_alloc, (unsigned long) 0);
   mgpw_pack_args(pblock, count - 1, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10);
   mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_EOD, DBX_DTYPE_STR);
   mg_add_block_head_size(pblock, pblock->len_used, DBX_CMND_GPREVIOUS);

   pmeth = mg_unpack_header((unsigned char *) pblock->buf_addr, NULL);
   pmeth->output_val.realloc = 2;
   rc = dbx_previous_x(pmeth);

   rc = mgpw_unpack_result(&(pmeth->output_val.svalue), key, 1);
   mgpw_postreq_buffers(pmeth, pblock);

   return rc;
}


MGPW_EXTFUN(int) mg_dbpreviousdata(int count, ydb_string_t *key, ydb_string_t *data, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10)
{
   int rc;
   DBXSTR *pblock;
   DBXMETH *pmeth;

   MGPW_ARG_COUNT(count, 3);
   MGPW_DB_CONNECTED(gblock, gresult);
   mgpw_prereq_buffers();

   pblock = &gblock;
   pblock->len_used = 0;
   mg_add_block_head(pblock, (unsigned long) pblock->len_alloc, (unsigned long) 0);
   mgpw_pack_args(pblock, count - 2, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10);
   mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_EOD, DBX_DTYPE_STR);
   mg_add_block_head_size(pblock, pblock->len_used, DBX_CMND_GPREVIOUSDATA);

   pmeth = mg_unpack_header((unsigned char *) pblock->buf_addr, NULL);
   pmeth->output_val.realloc = 2;
   rc = dbx_previous_data_x(pmeth);

   if (isc_net_connection)
      rc = mgpw_unpack_result2(&(pmeth->output_val.svalue), key, data, 1, 0);
   else
      rc = mgpw_unpack_result2(&(pmeth->output_val.svalue), data, key, 1, 1);

   mgpw_postreq_buffers(pmeth, pblock);

   return rc;
}


MGPW_EXTFUN(int) mg_dbincrement(int count, ydb_string_t *data, ydb_string_t *increment, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10)
{
   int rc;
   DBXSTR *pblock;
   DBXMETH *pmeth;

   MGPW_ARG_COUNT(count, 3);
   MGPW_DB_CONNECTED(gblock, gresult);
   mgpw_prereq_buffers();

   pblock = &gblock;
   pblock->len_used = 0;
   mg_add_block_head(pblock, (unsigned long) pblock->len_alloc, (unsigned long) 0);
   mgpw_pack_args(pblock, count - 2, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10);
   mg_add_block_data(pblock, (unsigned char *) increment->address, (unsigned long) increment->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
   mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_EOD, DBX_DTYPE_STR);
   mg_add_block_head_size(pblock, pblock->len_used, DBX_CMND_GINCREMENT);

   pmeth = mg_unpack_header((unsigned char *) pblock->buf_addr, NULL);
   pmeth->output_val.realloc = 2;
   rc = dbx_increment_x(pmeth);

   rc = mgpw_unpack_result(&(pmeth->output_val.svalue), data, 1);
   mgpw_postreq_buffers(pmeth, pblock);

   return rc;
}


MGPW_EXTFUN(int) mg_dblock(int count, ydb_string_t *result, ydb_string_t *timeout, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10)
{
   int rc;
   DBXSTR *pblock;
   DBXMETH *pmeth;

   MGPW_ARG_COUNT(count, 3);
   MGPW_DB_CONNECTED(gblock, gresult);
   mgpw_prereq_buffers();

   pblock = &gblock;
   pblock->len_used = 0;

   mg_add_block_head(pblock, (unsigned long) pblock->len_alloc, (unsigned long) 0);
   mgpw_pack_args(pblock, count - 2, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10);
   mg_add_block_data(pblock, (unsigned char *) timeout->address, (unsigned long) timeout->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
   mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_EOD, DBX_DTYPE_STR);
   mg_add_block_head_size(pblock, pblock->len_used, DBX_CMND_GLOCK);

   pmeth = mg_unpack_header((unsigned char *) pblock->buf_addr, NULL);
   pmeth->output_val.realloc = 2;
   rc = dbx_lock_x(pmeth);

   rc = mgpw_unpack_result(&(pmeth->output_val.svalue), result, 1);
   mgpw_postreq_buffers(pmeth, pblock);

   return rc;
}


MGPW_EXTFUN(int) mg_dbunlock(int count, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10)
{
   int rc;
   DBXSTR *pblock;
   DBXMETH *pmeth;
   ydb_string_t *presult;

   MGPW_ARG_COUNT(count, 1);
   MGPW_DB_CONNECTED(gblock, gresult);
   mgpw_prereq_buffers();

   pblock = &gblock;
   pblock->len_used = 0;
   presult = &gresult;
   presult->length = gresult_size;

   mg_add_block_head(pblock, (unsigned long) pblock->len_alloc, (unsigned long) 0);
   mgpw_pack_args(pblock, count, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10);
   mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_EOD, DBX_DTYPE_STR);
   mg_add_block_head_size(pblock, pblock->len_used, DBX_CMND_GUNLOCK);

   pmeth = mg_unpack_header((unsigned char *) pblock->buf_addr, NULL);
   pmeth->output_val.realloc = 2;
   rc = dbx_unlock_x(pmeth);

   rc = mgpw_unpack_result(&(pmeth->output_val.svalue), presult, 0);
   mgpw_postreq_buffers(pmeth, pblock);

   return rc;
}


MGPW_EXTFUN(int) mg_dbtstart(int count)
{
   int rc;
   DBXSTR *pblock;
   ydb_string_t *presult;

   MGPW_ARG_COUNT(count, 0);
   MGPW_DB_CONNECTED(gblock, gresult);

   pblock = &gblock;
   pblock->len_used = 0;
   presult = &gresult;
   presult->length = gresult_size;

   mg_add_block_head(pblock, (unsigned long) pblock->len_alloc, (unsigned long) 0);
   mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_EOD, DBX_DTYPE_STR);
   mg_add_block_head_size(pblock, pblock->len_used, DBX_CMND_TSTART);

   rc = dbx_tstart((unsigned char *) pblock->buf_addr, NULL);

   mgpw_unpack_result(pblock, presult, 0);

   return rc;
}


MGPW_EXTFUN(int) mg_dbtlevel(int count, ydb_string_t *data)
{
   int rc;
   DBXSTR *pblock;

   MGPW_ARG_COUNT(count, 1);
   MGPW_DB_CONNECTED(gblock, gresult);

   pblock = &gblock;
   pblock->len_used = 0;

   mg_add_block_head(pblock, (unsigned long) pblock->len_alloc, (unsigned long) 0);
   mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_EOD, DBX_DTYPE_STR);
   mg_add_block_head_size(pblock, pblock->len_used, DBX_CMND_TLEVEL);

   rc = dbx_tlevel((unsigned char *) pblock->buf_addr, NULL);

   mgpw_unpack_result(pblock, data, 1);

   return rc;
}


MGPW_EXTFUN(int) mg_dbtcommit(int count)
{
   int rc;
   DBXSTR *pblock;
   ydb_string_t *presult;

   MGPW_ARG_COUNT(count, 0);
   MGPW_DB_CONNECTED(gblock, gresult);

   pblock = &gblock;
   pblock->len_used = 0;
   presult = &gresult;
   presult->length = gresult_size;

   mg_add_block_head(pblock, (unsigned long) pblock->len_alloc, (unsigned long) 0);
   mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_EOD, DBX_DTYPE_STR);
   mg_add_block_head_size(pblock, pblock->len_used, DBX_CMND_TCOMMIT);

   rc = dbx_tcommit((unsigned char *) pblock->buf_addr, NULL);

   mgpw_unpack_result(pblock, presult, 0);

   return rc;
}


MGPW_EXTFUN(int) mg_dbtrollback(int count)
{
   int rc;
   DBXSTR *pblock;
   ydb_string_t *presult;

   MGPW_ARG_COUNT(count, 0);
   MGPW_DB_CONNECTED(gblock, gresult);

   pblock = &gblock;
   pblock->len_used = 0;
   presult = &gresult;
   presult->length = gresult_size;

   mg_add_block_head(pblock, (unsigned long) pblock->len_alloc, (unsigned long) 0);
   mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_EOD, DBX_DTYPE_STR);
   mg_add_block_head_size(pblock, pblock->len_used, DBX_CMND_TROLLBACK);

   rc = dbx_trollback((unsigned char *) pblock->buf_addr, NULL);

   mgpw_unpack_result(pblock, presult, 0);

   return rc;
}


MGPW_EXTFUN(int) mg_dbfunction(int count, ydb_string_t *data, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10)
{
   int rc;
   DBXSTR *pblock;
   DBXMETH *pmeth;

   MGPW_ARG_COUNT(count, 2);
   MGPW_DB_CONNECTED(gblock, gresult);
   mgpw_prereq_buffers();

/*
   if (isc_net_connection == 0) {
      strcpy(error_message, "ISC functions can only be invoked over network connections");
      error_message_len = (int) strlen(error_message);
      return YDB_FAILURE;
   }
*/
   pblock = &gblock;
   pblock->len_used = 0;
   mg_add_block_head(pblock, (unsigned long) pblock->len_alloc, (unsigned long) 0);
   mgpw_pack_args(pblock, count - 1, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10);
   mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_EOD, DBX_DTYPE_STR);
   mg_add_block_head_size(pblock, pblock->len_used, DBX_CMND_FUNCTION);

   pmeth = mg_unpack_header((unsigned char *) pblock->buf_addr, NULL);
   pmeth->output_val.realloc = 2;
   rc = dbx_function_x(pmeth);

   rc = mgpw_unpack_result(&(pmeth->output_val.svalue), data, 1);
   mgpw_postreq_buffers(pmeth, pblock);

   return rc;
}


MGPW_EXTFUN(int) mg_dbclassmethod(int count, ydb_string_t *data, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10)
{
   int rc;
   DBXSTR *pblock;
   DBXMETH *pmeth;

   MGPW_ARG_COUNT(count, 2);
   MGPW_DB_CONNECTED(gblock, gresult);
   mgpw_prereq_buffers();

/*
   if (isc_net_connection == 0) {
      strcpy(error_message, "ISC class methods can only be invoked over network connections");
      error_message_len = (int) strlen(error_message);
      return YDB_FAILURE;
   }
*/
   pblock = &gblock;
   pblock->len_used = 0;
   mg_add_block_head(pblock, (unsigned long) pblock->len_alloc, (unsigned long) 0);
   mgpw_pack_args(pblock, count - 1, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10);
   mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_EOD, DBX_DTYPE_STR);
   mg_add_block_head_size(pblock, pblock->len_used, DBX_CMND_CCMETH);

   pmeth = mg_unpack_header((unsigned char *) pblock->buf_addr, NULL);
   pmeth->output_val.realloc = 2;
   rc = dbx_classmethod_x(pmeth);

   rc = mgpw_unpack_result(&(pmeth->output_val.svalue), data, 1);
   mgpw_postreq_buffers(pmeth, pblock);

   return rc;
}


MGPW_EXTFUN(int) mg_dbgetproperty(int count, ydb_string_t *data, ydb_string_t *oref, ydb_string_t *pname)
{
   int rc;
   DBXSTR *pblock;
   DBXMETH *pmeth;

   MGPW_ARG_COUNT(count, 2);
   MGPW_DB_CONNECTED(gblock, gresult);
   mgpw_prereq_buffers();

/*
   if (isc_net_connection == 0) {
      strcpy(error_message, "ISC class properties can only be invoked over network connections");
      error_message_len = (int) strlen(error_message);
      return YDB_FAILURE;
   }
*/
   pblock = &gblock;
   pblock->len_used = 0;
   mg_add_block_head(pblock, (unsigned long) pblock->len_alloc, (unsigned long) 0);
   mg_add_block_data(pblock, (unsigned char *) oref->address, (unsigned long) oref->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
   mg_add_block_data(pblock, (unsigned char *) pname->address, (unsigned long) pname->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
   mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_EOD, DBX_DTYPE_STR);
   mg_add_block_head_size(pblock, pblock->len_used, DBX_CMND_CGETP);

   pmeth = mg_unpack_header((unsigned char *) pblock->buf_addr, NULL);
   pmeth->output_val.realloc = 2;
   rc = dbx_getproperty_x(pmeth);

   rc = mgpw_unpack_result(&(pmeth->output_val.svalue), data, 1);
   mgpw_postreq_buffers(pmeth, pblock);

   return rc;
}


MGPW_EXTFUN(int) mg_dbsetproperty(int count, ydb_string_t *data, ydb_string_t *oref, ydb_string_t *pname)
{
   int rc;
   DBXSTR *pblock;
   ydb_string_t *presult;

   MGPW_ARG_COUNT(count, 2);
   MGPW_DB_CONNECTED(gblock, gresult);
/*
   if (isc_net_connection == 0) {
      strcpy(error_message, "ISC class properties can only be invoked over network connections");
      error_message_len = (int) strlen(error_message);
      return YDB_FAILURE;
   }
*/
   pblock = &gblock;
   pblock->len_used = 0;
   presult = &gresult;
   presult->length = gresult_size;
   mg_add_block_head(pblock, (unsigned long) pblock->len_alloc, (unsigned long) 0);
   mg_add_block_data(pblock, (unsigned char *) oref->address, (unsigned long) oref->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
   mg_add_block_data(pblock, (unsigned char *) pname->address, (unsigned long) pname->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
   mg_add_block_data_ex(pblock, 0, (unsigned char *) data->address, (unsigned long) data->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
   mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_EOD, DBX_DTYPE_STR);
   mg_add_block_head_size(pblock, pblock->len_used, DBX_CMND_CSETP);

   rc = dbx_setproperty((unsigned char *) pblock->buf_addr, NULL);

   mgpw_unpack_result(pblock, presult, 0);

   return rc;
}


MGPW_EXTFUN(int) mg_dbmethod(int count, ydb_string_t *data, ydb_string_t *oref, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10)
{
   int rc;
   DBXSTR *pblock;
   DBXMETH *pmeth;

   MGPW_ARG_COUNT(count, 2);
   MGPW_DB_CONNECTED(gblock, gresult);
   mgpw_prereq_buffers();

/*
   if (isc_net_connection == 0) {
      strcpy(error_message, "ISC methods can only be invoked over network connections");
      error_message_len = (int) strlen(error_message);
      return YDB_FAILURE;
   }
*/
   pblock = &gblock;
   pblock->len_used = 0;
   mg_add_block_head(pblock, (unsigned long) pblock->len_alloc, (unsigned long) 0);
   mg_add_block_data(pblock, (unsigned char *) oref->address, (unsigned long) oref->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
   mgpw_pack_args(pblock, count - 2, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10);
   mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_EOD, DBX_DTYPE_STR);
   mg_add_block_head_size(pblock, pblock->len_used, DBX_CMND_CMETH);

   pmeth = mg_unpack_header((unsigned char *) pblock->buf_addr, NULL);
   pmeth->output_val.realloc = 2;
   rc = dbx_method_x(pmeth);

   rc = mgpw_unpack_result(&(pmeth->output_val.svalue), data, 1);
   mgpw_postreq_buffers(pmeth, pblock);

   return rc;
}


MGPW_EXTFUN(int) mg_dbcloseinstance(int count, ydb_string_t *oref)
{
   int rc;
   DBXSTR *pblock;
   ydb_string_t *presult;

   MGPW_ARG_COUNT(count, 1);
   MGPW_DB_CONNECTED(gblock, gresult);
/*
   if (isc_net_connection == 0) {
      strcpy(error_message, "ISC class properties can only be invoked over network connections");
      error_message_len = (int) strlen(error_message);
      return YDB_FAILURE;
   }
*/
   pblock = &gblock;
   pblock->len_used = 0;
   presult = &gresult;
   presult->length = gresult_size;
   mg_add_block_head(pblock, (unsigned long) pblock->len_alloc, (unsigned long) 0);
   mg_add_block_data(pblock, (unsigned char *) oref->address, (unsigned long) oref->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
   mg_add_block_data(pblock, (unsigned char *) "", (unsigned long) 0, DBX_DSORT_EOD, DBX_DTYPE_STR);
   mg_add_block_head_size(pblock, pblock->len_used, DBX_CMND_CCLOSE);

   rc = dbx_closeinstance((unsigned char *) pblock->buf_addr, NULL);

   mgpw_unpack_result(pblock, presult, 0);

   return rc;
}


/* v1.3.7 */
MGPW_EXTFUN(int) mg_dbgetstring(int count, ydb_string_t *data, ydb_string_t *index, ydb_string_t *chunkno)
{
   int idx, cn;
   unsigned long avail, get;
   char buffer[64];

   MGPW_ARG_COUNT(count, 1);
   MGPW_DB_CONNECTED(gblock, gresult);

   cn = 0;
   get = 0;
   avail = 0;
   idx = OUTPUT_STRING_IDX;
   if (count > 1 && index->length < 32) {
      strncpy(buffer, index->address, index->length);
      idx = (int) strtol(buffer, NULL, 10);
      if (idx == -2) {
         idx = OUTPUT_STRING_IDX - 1;
      }
      else if (idx < 0 || idx > 10) {
         idx = OUTPUT_STRING_IDX;
      }
   }
   if (string_stack[idx].str.address != NULL && string_stack[idx].status == 1) {
      avail = (string_stack[idx].data_len - string_stack[idx].sent_len);
      if (avail < 1) {
         avail = 0;
      }
   }
   get = avail;
   if (avail > data->length) {
      get = data->length;
   }
   if (get > 0) {
      memcpy((void *) data->address, (void *) (string_stack[idx].str.address + string_stack[idx].offset + string_stack[idx].sent_len), (size_t) get);
      data->length = get;
      string_stack[idx].chunk_no ++;
      string_stack[idx].sent_len += get;
      cn = string_stack[idx].chunk_no;
   }
   else {
      data->address[0] = '\0';
      data->length = 0;
   }
   if (count > 2) {
      sprintf(chunkno->address, "%d", cn);
      chunkno->length = (unsigned long) strtol(chunkno->address, NULL, 10);
   }

   return YDB_OK;
}


MGPW_EXTFUN(int) mg_dbputstring(int count, ydb_string_t *data, ydb_string_t *index, ydb_string_t *chunkno)
{
   int idx;
   unsigned long bsize;
   char *p;
   char buffer[64];

   MGPW_ARG_COUNT(count, 2);
   MGPW_DB_CONNECTED(gblock, gresult);

   idx = 0;
   if (count > 1 && index->length < 32) {
      strncpy(buffer, index->address, index->length);
      idx = (int) strtol(buffer, NULL, 10);
      if (idx > 10) {
         idx = 0;
      }
   }
   if (string_stack[idx].str.address == NULL) {
      string_stack[idx].str.address = (char *) mg_malloc(DBX_LS_BUFFER * sizeof(char), 0);
      if (string_stack[idx].str.address) {
         string_stack[idx].len_alloc = DBX_LS_BUFFER;
         string_stack[idx].str.length = 0;
         string_stack[idx].chunk_no = 0;
         string_stack[idx].offset = 0;
         string_stack[idx].data_len = 0;
         string_stack[idx].sent_len = 0;
         string_stack[idx].status = 1;
      }
      else {
         return YDB_FAILURE;
      }
   }
   if ((string_stack[idx].str.length + data->length) > string_stack[idx].len_alloc) {
      bsize = (string_stack[idx].str.length + data->length + 256);
      p = (char *) mg_malloc(bsize * sizeof(char), 0);
      if (!p) {
         return YDB_FAILURE;
      }
      memcpy((void *) p, (void *) string_stack[idx].str.address, (size_t) string_stack[idx].str.length);
      mg_free((void *) string_stack[idx].str.address, 0);
      string_stack[idx].str.address = p;
      string_stack[idx].len_alloc = bsize;
   }
   memcpy((void *) (string_stack[idx].str.address + string_stack[idx].str.length), (void *) data->address, (size_t) data->length);
   string_stack[idx].str.length += data->length;
   string_stack[idx].data_len = string_stack[idx].str.length;
   string_stack[idx].chunk_no ++;

   if (count > 2) {
      sprintf(chunkno->address, "%d", string_stack[idx].chunk_no);
      chunkno->length = (unsigned long) strtol(chunkno->address, NULL, 10);
   }

   return YDB_OK;
}


/* v1.2.2 */
#if !defined(_WIN32)
MGPW_EXTFUN(int) mg_tcp_options(int count, ydb_string_t *options, ydb_string_t *error)
{
   return YDB_OK;
}


MGPW_EXTFUN(int) mg_tcpserver_init(int count, ydb_int_t port, ydb_string_t *options, ydb_string_t *error)
{
   int rc;

   error->address[0] = '\0';
   error->length = 0;

   rc = mgpw_tcpsrv_init((int) port, options->address, error->address);
   if (rc != YDB_OK) {
      error->length = (unsigned long) strlen(error->address);
   }

   return YDB_OK;
}


MGPW_EXTFUN(int) mg_tcpserver_accept(int count, ydb_string_t *key, ydb_string_t *error)
{
   int rc;

   error->address[0] = '\0';
   error->length = 0;
   if (key->length == 0) {
      key->address[0] = '\0';
   }
   rc = mgpw_tcpsrv_accept(key->address, error->address);
   key->length = (unsigned long) strlen(key->address);
   if (rc != YDB_OK) {
      error->length = (unsigned long) strlen(error->address);
   }

   return YDB_OK;
}


MGPW_EXTFUN(int) mg_tcpserver_close(int count, ydb_string_t *key)
{
   int rc;

   rc = mgpw_tcpsrv_close(key->address);

   return rc;
}


MGPW_EXTFUN(int) mg_tcpchild_init(int count, ydb_string_t *key, ydb_string_t *options, ydb_string_t *error)
{
   int rc;

   error->address[0] = '\0';
   error->length = 0;

   rc = mgpw_domsrv_recvfd(key->address, options->address, error->address);
   key->length = (unsigned long) strlen(key->address);
   if (rc != YDB_OK) {
      error->length = (unsigned long) strlen(error->address);
   }

   return YDB_OK;
}


MGPW_EXTFUN(int) mg_tcpchild_send(int count, ydb_string_t *data, ydb_int_t flush, ydb_string_t *error)
{
   int rc;

   error->address[0] = '\0';
   error->length = 0;

   rc = mgpw_tcpsrv_send(data->address, (int) data->length, (int) flush, (char *) error->address);
   if (error->address[0]) {
      error->length = (unsigned long) strlen(error->address);
   }

   return YDB_OK;
}


MGPW_EXTFUN(int) mg_tcpchild_recv(int count, ydb_string_t *data, ydb_int_t len, ydb_int_t timeout, ydb_string_t *error)
{
   int rc;
   int dsize;

   error->address[0] = '\0';
   error->length = 0;
   data->address[0] = '\0';
   data->length = 0;
   dsize = (WORK_BUFFER - 1);

   rc = mgpw_tcpsrv_recv(data->address, (int) dsize, (int) len, (int) timeout, error->address);
   if (error->address[0]) {
      error->length = (unsigned long) strlen(error->address);
   }
   if (rc >= 0) {
      data->length = rc;
   }

   return YDB_OK;
}


MGPW_EXTFUN(int) mg_tcpchild_recv_ascii(int count, ydb_int_t *data, ydb_int_t timeout, ydb_string_t *error)
{
   int rc;
   char buffer[8];

   error->address[0] = '\0';
   error->length = 0;

   rc = mgpw_tcpsrv_recv(buffer, (int) 7, (int) 1, (int) timeout, error->address);
   if (error->address[0]) {
      error->length = (unsigned long) strlen(error->address);
   }
   if (rc >= 0) {
      *data = (ydb_int_t) buffer[0];
   }

   return YDB_OK;
}


MGPW_EXTFUN(int) mg_tcpchild_recv_message(int count, ydb_string_t *data, ydb_int_t *len, ydb_int_t *cmnd, ydb_int_t timeout, ydb_string_t *error)
{
   int rc;
   int dsize;

   error->address[0] = '\0';
   error->length = 0;
   data->address[0] = '\0';
   data->length = 0;
   dsize = (WORK_BUFFER - 1);

   rc = mgpw_tcpsrv_recv_message(data->address, (int) dsize, (int *) len, (int *) cmnd, (int) timeout, error->address);
   if (error->address[0]) {
      error->length = (unsigned long) strlen(error->address);
   }
   if (rc >= 0) {
      data->length = rc;
   }

   return YDB_OK;
}


MGPW_EXTFUN(int) mg_tcpchild_close(int count)
{
   int rc;

   rc = mgpw_tcpsrv_close("");

   return rc;
}
#endif /* #if !defined(_WIN32) */


int mgpw_crypt_load_library(MGPWCRYPTSO *p_crypt_so)
{
   int n, result;
   char primlib[MGPW_ERROR_SIZE], primerr[MGPW_ERROR_SIZE];
   char fun[64];
   char *libnam[16];

   strcpy(p_crypt_so->dbname, "Crypto");

   n = 0;
   if (p_crypt_so->libnam[0]) {
      libnam[n ++] = (char *) p_crypt_so->libnam;
   }
   else {
#if defined(_WIN32)
      libnam[n ++] = (char *) MGPW_CRYPT_DLL;
#else
#if defined(MACOSX)
      libnam[n ++] = (char *) MGPW_CRYPT_DYLIB;
      libnam[n ++] = (char *) MGPW_CRYPT_SO;
#else
      libnam[n ++] = (char *) MGPW_CRYPT_SO;
      libnam[n ++] = (char *) MGPW_CRYPT_DYLIB;
#endif
#endif
   }

   libnam[n ++] = NULL;

   for (n = 0; libnam[n]; n ++) {

      p_crypt_so->p_library = mgpw_dso_load(libnam[n]);
      if (p_crypt_so->p_library) {
         if (!p_crypt_so->libnam[0]) {
            strcpy(p_crypt_so->libnam, libnam[n]);
         }
         break;
      }

      if (!n) {
         int len1, len2;
         char *p;
#if defined(_WIN32)
         DWORD errorcode;
         LPVOID lpMsgBuf;

         lpMsgBuf = NULL;
         errorcode = GetLastError();
         sprintf(error_message, "Error loading %s Library: %s; Error Code : %ld",  p_crypt_so->dbname, primlib, errorcode);
         len2 = (int) strlen(error_message);
         len1 = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                        NULL,
                        errorcode,
                        /* MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), */
                        MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
                        (LPTSTR) &lpMsgBuf,
                        0,
                        NULL 
                        );
         if (lpMsgBuf && len1 > 0 && (MGPW_ERROR_SIZE - len2) > 30) {
            strncpy(primerr, (const char *) lpMsgBuf, MGPW_ERROR_SIZE - 1);
            p = strstr(primerr, "\r\n");
            if (p)
               *p = '\0';
            len1 = (MGPW_ERROR_SIZE - (len2 + 10));
            if (len1 < 1)
               len1 = 0;
            primerr[len1] = '\0';
            p = strstr(primerr, "%1");
            if (p) {
               *p = 'I';
               *(p + 1) = 't';
            }
            strcat(error_message, " (");
            strcat(error_message, primerr);
            strcat(error_message, ")");
         }
         if (lpMsgBuf) {
            LocalFree(lpMsgBuf);
         }
#else
         p = (char *) dlerror();
         sprintf(primerr, "Cannot load %s library: Error Code: %d", p_crypt_so->dbname, errno);
         len2 = strlen(error_message);
         if (p) {
            strncpy(primerr, p, MGPW_ERROR_SIZE - 1);
            primerr[MGPW_ERROR_SIZE - 1] = '\0';
            len1 = (MGPW_ERROR_SIZE - (len2 + 10));
            if (len1 < 1)
               len1 = 0;
            primerr[len1] = '\0';
            strcat(error_message, " (");
            strcat(error_message, primerr);
            strcat(error_message, ")");
         }
#endif
      }
   }

   if (!p_crypt_so->p_library) {
      goto mgpw_crypt_load_library;
   }

   strcpy(fun, "OpenSSL_version");
   p_crypt_so->p_OpenSSL_version = (const char * (*) (int)) mgpw_dso_sym(p_crypt_so->p_library, (char *) fun);
   if (!p_crypt_so->p_OpenSSL_version) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_crypt_so->dbname, p_crypt_so->libnam, fun);
      goto mgpw_crypt_load_library;
   }

   strcpy(fun, "HMAC");
   p_crypt_so->p_HMAC = (unsigned char * (*) (const EVP_MD *, const void *, int, const unsigned char *, int, unsigned char *, unsigned int *)) mgpw_dso_sym(p_crypt_so->p_library, (char *) fun);
   if (!p_crypt_so->p_HMAC) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_crypt_so->dbname, p_crypt_so->libnam, fun);
      goto mgpw_crypt_load_library;
   }
   strcpy(fun, "EVP_sha1");
   p_crypt_so->p_EVP_sha1 = (const EVP_MD * (*) (void)) mgpw_dso_sym(p_crypt_so->p_library, (char *) fun);
   if (!p_crypt_so->p_EVP_sha1) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_crypt_so->dbname, p_crypt_so->libnam, fun);
      goto mgpw_crypt_load_library;
   }
   strcpy(fun, "EVP_sha256");
   p_crypt_so->p_EVP_sha256 = (const EVP_MD * (*) (void)) mgpw_dso_sym(p_crypt_so->p_library, (char *) fun);
   if (!p_crypt_so->p_EVP_sha256) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_crypt_so->dbname, p_crypt_so->libnam, fun);
      goto mgpw_crypt_load_library;
   }
   strcpy(fun, "EVP_sha512");
   p_crypt_so->p_EVP_sha512 = (const EVP_MD * (*) (void)) mgpw_dso_sym(p_crypt_so->p_library, (char *) fun);
   if (!p_crypt_so->p_EVP_sha512) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_crypt_so->dbname, p_crypt_so->libnam, fun);
      goto mgpw_crypt_load_library;
   }

   strcpy(fun, "EVP_md5");
   p_crypt_so->p_EVP_md5 = (const EVP_MD * (*) (void)) mgpw_dso_sym(p_crypt_so->p_library, (char *) fun);
   if (!p_crypt_so->p_EVP_md5) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_crypt_so->dbname, p_crypt_so->libnam, fun);
      goto mgpw_crypt_load_library;
   }

   strcpy(fun, "SHA1");
   p_crypt_so->p_SHA1 = (unsigned char * (*) (const unsigned char *, unsigned long, unsigned char *)) mgpw_dso_sym(p_crypt_so->p_library, (char *) fun);
   if (!p_crypt_so->p_SHA1) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_crypt_so->dbname, p_crypt_so->libnam, fun);
      goto mgpw_crypt_load_library;
   }
   strcpy(fun, "SHA256");
   p_crypt_so->p_SHA256 = (unsigned char * (*) (const unsigned char *, unsigned long, unsigned char *)) mgpw_dso_sym(p_crypt_so->p_library, (char *) fun);
   if (!p_crypt_so->p_SHA256) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_crypt_so->dbname, p_crypt_so->libnam, fun);
      goto mgpw_crypt_load_library;
   }
   strcpy(fun, "SHA512");
   p_crypt_so->p_SHA512 = (unsigned char * (*) (const unsigned char *, unsigned long, unsigned char *)) mgpw_dso_sym(p_crypt_so->p_library, (char *) fun);
   if (!p_crypt_so->p_SHA512) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_crypt_so->dbname, p_crypt_so->libnam, fun);
      goto mgpw_crypt_load_library;
   }
   strcpy(fun, "MD5");
   p_crypt_so->p_MD5 = (unsigned char * (*) (const unsigned char *, unsigned long, unsigned char *)) mgpw_dso_sym(p_crypt_so->p_library, (char *) fun);
   if (!p_crypt_so->p_MD5) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_crypt_so->dbname, p_crypt_so->libnam, fun);
      goto mgpw_crypt_load_library;
   }

   p_crypt_so->loaded = 1;

mgpw_crypt_load_library:

   if (error_message[0]) {
      error_message_len = (int) strlen(error_message);
      p_crypt_so->loaded = 0;
      error_code = 1009;
      result = YDB_FAILURE;
      return result;
   }

   return YDB_OK;
}


int mgpw_pack_args(DBXSTR *pblock, int count, ydb_string_t *k1, ydb_string_t *k2, ydb_string_t *k3, ydb_string_t *k4, ydb_string_t *k5, ydb_string_t *k6, ydb_string_t *k7, ydb_string_t *k8, ydb_string_t *k9, ydb_string_t *k10)
{
   int n;
   
   n = 0;
   mg_add_block_data(pblock, (unsigned char *) k1->address, (unsigned long) k1->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
   if (++ n >= count)
      return YDB_OK;
   mg_add_block_data_ex(pblock, n, (unsigned char *) k2->address, (unsigned long) k2->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
   if (++ n >= count)
      return YDB_OK;
   mg_add_block_data_ex(pblock, n, (unsigned char *) k3->address, (unsigned long) k3->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
   if (++ n >= count)
      return YDB_OK;
   mg_add_block_data_ex(pblock, n, (unsigned char *) k4->address, (unsigned long) k4->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
   if (++ n >= count)
      return YDB_OK;
   mg_add_block_data_ex(pblock, n, (unsigned char *) k5->address, (unsigned long) k5->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
   if (++ n >= count)
      return YDB_OK;
   mg_add_block_data_ex(pblock, n, (unsigned char *) k6->address, (unsigned long) k6->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
   if (++ n >= count)
      return YDB_OK;
   mg_add_block_data_ex(pblock, n, (unsigned char *) k7->address, (unsigned long) k7->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
   if (++ n >= count)
      return YDB_OK;
   mg_add_block_data_ex(pblock, n, (unsigned char *) k8->address, (unsigned long) k8->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
   if (++ n >= count)
      return YDB_OK;
   mg_add_block_data_ex(pblock, n, (unsigned char *) k9->address, (unsigned long) k9->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
   if (++ n >= count)
      return YDB_OK;
   mg_add_block_data_ex(pblock, n, (unsigned char *) k10->address, (unsigned long) k10->length, DBX_DSORT_DATA, DBX_DTYPE_STR);
   if (++ n >= count)
      return YDB_OK;

   return YDB_OK;
}


int mg_add_block_data_ex(DBXSTR *pblock, int idx, unsigned char *data, unsigned long data_len, int dsort, int dtype)
{
   if (idx >= 0 && idx < (OUTPUT_STRING_IDX - 1) && string_stack[idx].status == 1 && string_stack[idx].str.address != NULL) {
      mg_add_block_data(pblock, (unsigned char *) string_stack[idx].str.address, (unsigned long) string_stack[idx].str.length, DBX_DSORT_DATA, DBX_DTYPE_STR);
   }
   else {
      mg_add_block_data(pblock, (unsigned char *) data, (unsigned long) data_len, DBX_DSORT_DATA, DBX_DTYPE_STR);
   }

   return YDB_OK;
}


int mgpw_unpack_result(DBXSTR *pblock, ydb_string_t *out, int stack_string)
{
   int rc, dsort, dtype;
   unsigned long data_len;

   data_len = mg_get_block_size(pblock, 0, &dsort, &dtype);
   if (dsort == DBX_DSORT_ERROR) {
      memcpy((void *) error_message, (void *) (pblock->buf_addr + 5), (size_t) data_len);
      error_message_len = data_len;
      out->length = 0;
      rc = YDB_FAILURE;
   }
   else {
      if (data_len > out->length) {
         if (stack_string) { /* v1.3.7 */
            /* Cache: 3641144 YottaDB: 1048576 */
            memcpy((void *) out->address, (void *) (pblock->buf_addr + 5), (size_t) out->length);
            string_stack[OUTPUT_STRING_IDX].status = 1;
            string_stack[OUTPUT_STRING_IDX].chunk_no = 1;
            string_stack[OUTPUT_STRING_IDX].data_len = data_len;
            string_stack[OUTPUT_STRING_IDX].sent_len = out->length;
            string_stack[OUTPUT_STRING_IDX].offset = 5;
            string_stack[OUTPUT_STRING_IDX].len_alloc = pblock->len_alloc;
            string_stack[OUTPUT_STRING_IDX].str.address = pblock->buf_addr;
            string_stack[OUTPUT_STRING_IDX].str.length = pblock->len_used;
            rc = YDB_OK;
         }
         else {
            sprintf(error_message, "Maximum string length (%lu Bytes) exceeded", out->length);
            error_message_len = (int) strlen(error_message);
            out->length = 0;
            rc = YDB_FAILURE;
         }
      }
      else {
         memcpy((void *) out->address, (void *) (pblock->buf_addr + 5), (size_t) data_len);
         out->length = data_len;
         rc = YDB_OK;
      }
   }

   return rc;
}


int mgpw_unpack_result2(DBXSTR *pblock, ydb_string_t *out1, ydb_string_t *out2, int stack_string, int context)
{
   int rc, dsort, dtype, idx1, idx2;
   unsigned long data_len, offset;

   rc = YDB_OK;
   if (context == 0) {
      idx1 = OUTPUT_STRING_IDX - 1;
      idx2 = OUTPUT_STRING_IDX;
   }
   else {
      idx1 = OUTPUT_STRING_IDX;
      idx2 = OUTPUT_STRING_IDX - 1;
   }
   data_len = mg_get_block_size(pblock, 0, &dsort, &dtype);
   if (dsort == DBX_DSORT_ERROR) {
      memcpy((void *) error_message, (void *) (pblock->buf_addr + 5), (size_t) data_len);
      error_message_len = data_len;
      out1->length = 0;
      out2->length = 0;
      rc = YDB_FAILURE;
   }
   else {
      offset = 5;
      data_len = mg_get_block_size(pblock, offset, &dsort, &dtype);
      offset += 5;

      if (data_len > out1->length) {
         if (stack_string) { /* v1.3.7 */
            /* Cache: 3641144 YottaDB: 1048576 */
            memcpy((void *) out1->address, (void *) (pblock->buf_addr + offset), (size_t) out1->length);
            string_stack[idx1].status = 1;
            string_stack[idx1].chunk_no = 1;
            string_stack[idx1].data_len = data_len;
            string_stack[idx1].sent_len = out1->length;
            string_stack[idx1].offset = offset;
            string_stack[idx1].len_alloc = pblock->len_alloc;
            string_stack[idx1].str.address = pblock->buf_addr;
            string_stack[idx1].str.length = pblock->len_used;
            rc = YDB_OK;
         }
         else {
            sprintf(error_message, "Maximum string length (%lu Bytes) exceeded", out1->length);
            error_message_len = (int) strlen(error_message);
            out1->length = 0;
            rc = YDB_FAILURE;
         }
      }
      else {
         memcpy((void *) out1->address, (void *) (pblock->buf_addr + offset), (size_t) data_len);
         out1->length = data_len;
         rc = YDB_OK;
      }
      if (rc == YDB_OK) {
         offset += data_len;
         data_len = mg_get_block_size(pblock, offset, &dsort, &dtype);
         offset += 5;
         if (data_len > out2->length) {
            if (stack_string) { /* v1.3.7 */
               /* Cache: 3641144 YottaDB: 1048576 */
               memcpy((void *) out2->address, (void *) (pblock->buf_addr + offset), (size_t) out2->length);
               string_stack[idx2].status = 1;
               string_stack[idx2].chunk_no = 1;
               string_stack[idx2].data_len = data_len;
               string_stack[idx2].sent_len = out2->length;
               string_stack[idx2].offset = offset;
               string_stack[idx2].len_alloc = pblock->len_alloc;
               string_stack[idx2].str.address = pblock->buf_addr;
               string_stack[idx2].str.length = pblock->len_used;
               rc = YDB_OK;
            }
            else {
               sprintf(error_message, "Maximum string length (%lu Bytes) exceeded", out2->length);
               error_message_len = (int) strlen(error_message);
               out2->length = 0;
               rc = YDB_FAILURE;
            }
         }
         else {
            memcpy((void *) out2->address, (void *) (pblock->buf_addr + offset), (size_t) data_len);
            out2->length = data_len;
            rc = YDB_OK;
         }
      }
      else {
         out2->length = 0;
      }
   }

   return rc;
}


/* v1.3.7 */
int mgpw_prereq_buffers()
{
   string_stack[OUTPUT_STRING_IDX].str.address = NULL;
   string_stack[OUTPUT_STRING_IDX].str.length = 0;
   string_stack[OUTPUT_STRING_IDX].len_alloc = 0;
   string_stack[OUTPUT_STRING_IDX].data_len = 0;
   string_stack[OUTPUT_STRING_IDX].sent_len = 0;
   string_stack[OUTPUT_STRING_IDX].offset = 0;
   string_stack[OUTPUT_STRING_IDX].chunk_no = 0;
   string_stack[OUTPUT_STRING_IDX].status = 0;

   string_stack[OUTPUT_STRING_IDX - 1].str.address = NULL;
   string_stack[OUTPUT_STRING_IDX - 1].str.length = 0;
   string_stack[OUTPUT_STRING_IDX - 1].len_alloc = 0;
   string_stack[OUTPUT_STRING_IDX - 1].data_len = 0;
   string_stack[OUTPUT_STRING_IDX - 1].sent_len = 0;
   string_stack[OUTPUT_STRING_IDX - 1].offset = 0;
   string_stack[OUTPUT_STRING_IDX - 1].chunk_no = 0;
   string_stack[OUTPUT_STRING_IDX - 1].status = 0;

   return YDB_OK;
}


/* v1.3.7 */
int mgpw_postreq_buffers(DBXMETH *pmeth, DBXSTR *pblock)
{
   int n;

   pblock->buf_addr = pmeth->output_val.svalue.buf_addr;
   pblock->len_alloc = pmeth->output_val.svalue.len_alloc;
   pblock->len_used = pmeth->output_val.svalue.len_used;

   for (n = 0; n < (OUTPUT_STRING_IDX - 1); n ++) {
      if (string_stack[n].str.address && string_stack[n].str.address != pblock->buf_addr) {
         mg_free((void *) string_stack[n].str.address, 0);
         string_stack[n].str.address = NULL;
         string_stack[n].str.length = 0;
         string_stack[n].len_alloc = 0;
         string_stack[n].offset = 0;
         string_stack[n].chunk_no = 0;
         string_stack[n].status = 0;
      }
   }

   return YDB_OK;
}


int mgpw_set_size(unsigned char *str, unsigned long data_len)
{
   str[0] = (unsigned char) (data_len >> 0);
   str[1] = (unsigned char) (data_len >> 8);
   str[2] = (unsigned char) (data_len >> 16);
   str[3] = (unsigned char) (data_len >> 24);

   return 0;
}


unsigned long mgpw_get_size(unsigned char *str)
{
   unsigned long size;

   size = ((unsigned char) str[0]) | (((unsigned char) str[1]) << 8) | (((unsigned char) str[2]) << 16) | (((unsigned char) str[3]) << 24);
   return size;
}


int mgpw_lcase(char *string)
{
#ifdef _UNICODE

   CharLowerA(string);
   return 1;

#else

   int n, chr;

   n = 0;
   while (string[n] != '\0') {
      chr = (int) string[n];
      if (chr >= 65 && chr <= 90)
         string[n] = (char) (chr + 32);
      n ++;
   }
   return 1;

#endif
}


int mgpw_log_init(MGPWLOG *p_log)
{
   p_log->log_errors = 0;
   p_log->log_file[0] = '\0';
   p_log->log_level[0] = '\0';

   return 0;
}


int mgpw_log_event(MGPWLOG *p_log, char *message, char *title, int level)
{
   int len, n;
   char timestr[64], heading[256], buffer[2048];
   char *p_buffer;
   time_t now = 0;
#if defined(_WIN32)
   HANDLE hLogfile = 0;
   DWORD dwPos = 0, dwBytesWritten = 0;
#else
   FILE *fp = NULL;
   struct flock lock;
#endif

   now = time(NULL);
   sprintf(timestr, "%s", ctime(&now));
   for (n = 0; timestr[n] != '\0'; n ++) {
      if ((unsigned int) timestr[n] < 32) {
         timestr[n] = '\0';
         break;
      }
   }

   sprintf(heading, ">>> Time: %s; Build: %s pid=%lu;tid=%lu;", timestr, MGPW_VERSION, (unsigned long) mgpw_current_process_id(), (unsigned long) mgpw_current_thread_id());

   len = (int) strlen(heading) + (int) strlen(title) + (int) strlen(message) + 20;

   if (len < 2000)
      p_buffer = buffer;
   else
      p_buffer = (char *) mg_malloc(sizeof(char) * len, 0);

   if (p_buffer == NULL)
      return 0;

   p_buffer[0] = '\0';
   strcpy(p_buffer, heading);
   strcat(p_buffer, "\r\n    ");
   strcat(p_buffer, title);
   strcat(p_buffer, "\r\n    ");
   strcat(p_buffer, message);
   len = (int) strlen(p_buffer) * sizeof(char);

#if defined(_WIN32)

   strcat(p_buffer, "\r\n");
   len = len + (2 * sizeof(char));
   hLogfile = CreateFileA(p_log->log_file, GENERIC_WRITE, FILE_SHARE_WRITE,
                         (LPSECURITY_ATTRIBUTES) NULL, OPEN_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, (HANDLE) NULL);
   dwPos = SetFilePointer(hLogfile, 0, (LPLONG) NULL, FILE_END);
   LockFile(hLogfile, dwPos, 0, dwPos + len, 0);
   WriteFile(hLogfile, (LPTSTR) p_buffer, len, &dwBytesWritten, NULL);
   UnlockFile(hLogfile, dwPos, 0, dwPos + len, 0);
   CloseHandle(hLogfile);

#else /* UNIX or VMS */

   strcat(p_buffer, "\n");
   fp = fopen(p_log->log_file, "a");
   if (fp) {

      lock.l_type = F_WRLCK;
      lock.l_start = 0;
      lock.l_whence = SEEK_SET;
      lock.l_len = 0;
      n = fcntl(fileno(fp), F_SETLKW, &lock);

      fputs(p_buffer, fp);
      fclose(fp);

      lock.l_type = F_UNLCK;
      lock.l_start = 0;
      lock.l_whence = SEEK_SET;
      lock.l_len = 0;
      n = fcntl(fileno(fp), F_SETLK, &lock);
   }

#endif

   if (p_buffer != buffer)
      free((void *) p_buffer);

   return 1;
}


int mgpw_log_buffer(MGPWLOG *p_log, char *buffer, int buffer_len, char *title, int level)
{
   unsigned int c, len, strt;
   int n, n1, nc, size;
   char tmp[16];
   char *p;

   for (n = 0, nc = 0; n < buffer_len; n ++) {
      c = (unsigned int) buffer[n];
      if (c < 32 || c > 126)
         nc ++;
   }

   size = buffer_len + (nc * 4) + 32;
   p = (char *) mg_malloc(sizeof(char) * size, 0);
   if (!p)
      return 0;

   if (nc) {

      for (n = 0, nc = 0; n < buffer_len; n ++) {
         c = (unsigned int) buffer[n];
         if (c < 32 || c > 126) {
            sprintf((char *) tmp, "%02x", c);
            len = (int) strlen(tmp);
            if (len > 2)
               strt = len - 2;
            else
               strt = 0;
            p[nc ++] = '\\';
            p[nc ++] = 'x';
            for (n1 = strt; tmp[n1]; n1 ++)
               p[nc ++] = tmp[n1];
         }
         else
            p[nc ++] = buffer[n];
      }
      p[nc] = '\0';
   }
   else {
      strncpy(p, buffer, buffer_len);
      p[buffer_len] = '\0';
   }

   mgpw_log_event(p_log, (char *) p, title, level);

   mg_free((void *) p, 0);

   return 1;
}


MGPWPLIB mgpw_dso_load(char * library)
{
   MGPWPLIB p_library;

#if defined(_WIN32)
   p_library = LoadLibraryA(library);
#else
#if defined(RTLD_DEEPBIND)
   p_library = dlopen(library, RTLD_NOW | RTLD_DEEPBIND);

#else
   p_library = dlopen(library, RTLD_NOW);
#endif
#endif

   return p_library;
}


MGPWPROC mgpw_dso_sym(MGPWPLIB p_library, char * symbol)
{
   MGPWPROC p_proc;

#if defined(_WIN32)
   p_proc = GetProcAddress(p_library, symbol);
#else
   p_proc  = (void *) dlsym(p_library, symbol);
#endif

   return p_proc;
}



int mgpw_dso_unload(MGPWPLIB p_library)
{

#if defined(_WIN32)
   FreeLibrary(p_library);
#else
   dlclose(p_library); 
#endif

   return 1;
}


MGPWTHID mgpw_current_thread_id(void)
{
#if defined(_WIN32)
   return (MGPWTHID) GetCurrentThreadId();
#else
   return (MGPWTHID) pthread_self();
#endif
}


unsigned long mgpw_current_process_id(void)
{
#if defined(_WIN32)
   return (unsigned long) GetCurrentProcessId();
#else
   return ((unsigned long) getpid());
#endif
}


int mgpw_mutex_create(MGPWMUTEX *p_mutex)
{
   int result;

   result = 0;
   if (p_mutex->created) {
      return result;
   }

#if defined(_WIN32)
   p_mutex->h_mutex = CreateMutex(NULL, FALSE, NULL);
   result = 0;
#else
   result = pthread_mutex_init(&(p_mutex->h_mutex), NULL);
#endif

   p_mutex->created = 1;
   p_mutex->stack = 0;
   p_mutex->thid = 0;

   return result;
}



int mgpw_mutex_lock(MGPWMUTEX *p_mutex, int timeout)
{
   int result;
   MGPWTHID tid;
#ifdef _WIN32
   DWORD result_wait;
#endif

   result = 0;

   if (!p_mutex->created) {
      return -1;
   }

   tid = mgpw_current_thread_id();
   if (p_mutex->thid == tid) {
      p_mutex->stack ++;
      /* printf("\r\n thread already owns lock : thid=%lu; stack=%d;\r\n", (unsigned long) tid, p_mutex->stack); */
      return 0; /* success - thread already owns lock */
   }

#if defined(_WIN32)
   if (timeout == 0) {
      result_wait = WaitForSingleObject(p_mutex->h_mutex, INFINITE);
   }
   else {
      result_wait = WaitForSingleObject(p_mutex->h_mutex, (timeout * 1000));
   }

   if (result_wait == WAIT_OBJECT_0) { /* success */
      result = 0;
   }
   else if (result_wait == WAIT_ABANDONED) {
      printf("\r\nmgpw_mutex_lock: Returned WAIT_ABANDONED state");
      result = -1;
   }
   else if (result_wait == WAIT_TIMEOUT) {
      printf("\r\nmgpw_mutex_lock: Returned WAIT_TIMEOUT state");
      result = -1;
   }
   else if (result_wait == WAIT_FAILED) {
      printf("\r\nmgpw_mutex_lock: Returned WAIT_FAILED state: Error Code: %d", GetLastError());
      result = -1;
   }
   else {
      printf("\r\nmgpw_mutex_lock: Returned Unrecognized state: %d", result_wait);
      result = -1;
   }
#else
   result = pthread_mutex_lock(&(p_mutex->h_mutex));
#endif

   p_mutex->thid = tid;
   p_mutex->stack = 0;

   return result;
}


int mgpw_mutex_unlock(MGPWMUTEX *p_mutex)
{
   int result;
   MGPWTHID tid;

   result = 0;

   if (!p_mutex->created) {
      return -1;
   }

   tid = mgpw_current_thread_id();
   if (p_mutex->thid == tid && p_mutex->stack) {
      /* printf("\r\n thread has stacked locks : thid=%lu; stack=%d;\r\n", (unsigned long) tid, p_mutex->stack); */
      p_mutex->stack --;
      return 0;
   }
   p_mutex->thid = 0;
   p_mutex->stack = 0;

#if defined(_WIN32)
   ReleaseMutex(p_mutex->h_mutex);
   result = 0;
#else
   result = pthread_mutex_unlock(&(p_mutex->h_mutex));
#endif /* #if defined(_WIN32) */

   return result;
}


int mgpw_mutex_destroy(MGPWMUTEX *p_mutex)
{
   int result;

   if (!p_mutex->created) {
      return -1;
   }

#if defined(_WIN32)
   CloseHandle(p_mutex->h_mutex);
   result = 0;
#else
   result = pthread_mutex_destroy(&(p_mutex->h_mutex));
#endif

   p_mutex->created = 0;

   return result;
}


int mgpw_init_critical_section(void *p_crit)
{
#if defined(_WIN32)
   InitializeCriticalSection((LPCRITICAL_SECTION) p_crit);
#endif

   return 0;
}


int mgpw_delete_critical_section(void *p_crit)
{
#if defined(_WIN32)
   DeleteCriticalSection((LPCRITICAL_SECTION) p_crit);
#endif

   return 0;
}


int mgpw_enter_critical_section(void *p_crit)
{
   int result;

#if defined(_WIN32)
   EnterCriticalSection((LPCRITICAL_SECTION) p_crit);
   result = 0;
#else
   result = pthread_mutex_lock((pthread_mutex_t *) p_crit);
#endif
   return result;
}


int mgpw_leave_critical_section(void *p_crit)
{
   int result;

#if defined(_WIN32)
   LeaveCriticalSection((LPCRITICAL_SECTION) p_crit);
   result = 0;
#else
   result = pthread_mutex_unlock((pthread_mutex_t *) p_crit);
#endif
   return result;
}


int mgpw_sleep(unsigned long msecs)
{
#if defined(_WIN32)

   Sleep((DWORD) msecs);

#else

#if 1
   unsigned int secs, msecs_rem;

   secs = (unsigned int) (msecs / 1000);
   msecs_rem = (unsigned int) (msecs % 1000);

   /* printf("\n   ===> msecs=%ld; secs=%ld; msecs_rem=%ld", msecs, secs, msecs_rem); */

   if (secs > 0) {
      sleep(secs);
   }
   if (msecs_rem > 0) {
      usleep((useconds_t) (msecs_rem * 1000));
   }

#else
   unsigned int secs;

   secs = (unsigned int) (msecs / 1000);
   if (secs == 0)
      secs = 1;
   sleep(secs);

#endif

#endif

   return 0;
}


char mgpw_b64_ntc(unsigned char n)
{
   if (n < 26)
      return 'A' + n;
   if (n < 52)
      return 'a' - 26 + n;

   if (n < 62)
      return '0' - 52 + n;
   if (n == 62)
      return '+';

   return '/';
}


unsigned char mgpw_b64_ctn(char c)
{

   if (c == '/')
      return 63;
   if (c == '+')
      return 62;
   if ((c >= 'A') && (c <= 'Z'))
      return c - 'A';
   if ((c >= 'a') && (c <= 'z'))
      return c - 'a' + 26;
   if ((c >= '0') && (c <= '9'))
      return c - '0' + 52;
   if (c == '=')
      return 80;
   return 100;
}


int mgpw_b64_encode(char *from, int length, char *to, int quads)
{
   int i = 0;
   char *tot = to;
   int qc = 0;
   unsigned char c;
   unsigned char d;

   while (i < length) {
      c = from[i];
      *to++ = (char) mgpw_b64_ntc((unsigned char) (c / 4));
      c = c * 64;
     
      i++;

      if (i >= length) {
         *to++ = mgpw_b64_ntc((unsigned char) (c / 4));
         *to++ = '=';
         *to++ = '=';
         break;
      }
      d = from[i];
      *to++ = mgpw_b64_ntc((unsigned char) (c / 4 + d / 16));
      d = d * 16;

      i++;


      if (i >= length) {
         *to++ = mgpw_b64_ntc((unsigned char) (d / 4));
         *to++ = '=';
         break;
      }
      c = from[i];
      *to++ = mgpw_b64_ntc((unsigned char) (d / 4 + c / 64));
      c=c * 4;

      i++;

      *to++ = mgpw_b64_ntc((unsigned char) (c / 4));

      qc ++;
      if (qc == quads) {
         *to++ = '\n';
         qc = 0;
      }
   }

   return ((int) (to - tot));
}


int mgpw_b64_decode(char *from, int length, char *to)
{
   unsigned char c, d, e, f;
   char A, B, C;
   int i;
   int add;
   char *tot = to;

   for (i = 0; i + 3 < length;) {
      add = 0;
      A = B = C = 0;
      c = d = e = f = 100;

      while ((c == 100) && (i < length))
         c = mgpw_b64_ctn(from[i++]);
      while ((d == 100) && (i < length))
         d = mgpw_b64_ctn(from[i++]);
      while ((e == 100) && (i < length))
         e = mgpw_b64_ctn(from[i++]);
      while ((f == 100) && (i < length))
         f = mgpw_b64_ctn(from[i++]);

      if (f == 100)
         return -1;

      if (c < 64) {
         A += c * 4;
         if (d < 64) {
            A += d / 16;

            B += d * 16;

            if (e < 64) {
               B += e / 4;
               C += e * 64;

               if (f < 64) {
                  C += f;
                  to[2] = C;
                  add += 1;

               }
               to[1] = B;
               add += 1;

            }
            to[0] = A;
            add += 1;
         }
      }
      to += add;

      if (f == 80)
         return ((int) (to - tot));
   }
   return ((int) (to - tot));
}


int mgpw_b64_enc_buffer_size(int l, int q)
{
   int ret;

   ret = (l / 3) * 4;
   if (l % 3 != 0)
      ret += 4;
   if (q != 0) {
      ret += (ret / (q * 4));
   }

   return ret;
}


int mgpw_b64_strip_enc_buffer(char *buf, int length)
{
   int i;
   int ret = 0;

   for (i = 0;i < length;i ++)
      if (mgpw_b64_ctn(buf[i]) != 100)
         buf[ret++] = buf[i];
 
   return ret;
}


int mgpw_hex_encode(char *from, int length, char *to)
{
   int n, len;
   unsigned int c, c1, c2;
   char *hex = "0123456789abcdef";

   for (n = 0, len = 0; n < length; n ++) {
      c = (unsigned int) from[n];
      c1 = (c / 16) % 16;
      c2 = (c % 16);
      to[len ++] = hex[c1];
      to[len ++] = hex[c2];
   }
   to[len] = '\0';
   return len;
}


unsigned long mgpw_crc32_checksum(char *buffer, size_t len)
{
   register unsigned long oldcrc32;

   oldcrc32 = 0xFFFFFFFF;

   for ( ; len; --len, ++ buffer) {
      oldcrc32 = UPDC32(*buffer, oldcrc32);
   }

   return ~oldcrc32;
}

#if !defined(_WIN32)
void * mgpw_stdin_listener(void *pargs)
{
   int rc, clilen;
   int fd;
   int pipefd[2];
   char buffer[256], error[512];

   fd = dup(STDIN_FILENO);
   pipe(pipefd);
   dup2(pipefd[0], STDIN_FILENO);
   close(pipefd[0]);

   pthread_mutex_lock(&mgpw_cond_mutex);
   mgpw_cond_flag = 1;
   pthread_cond_broadcast(&mgpw_cond);
   pthread_mutex_unlock(&mgpw_cond_mutex);

   while (1) {
      rc = mgpw_tcpsrv_recv(buffer, 255, 0, 0, error);
      if (rc < 0 && errno == EINTR) {
         continue;
      }
      if (rc < 1) {
         break;
      }
      buffer[rc] = '\0';
      rc = write(pipefd[1], buffer, rc);

      /* fflush(stdin); - not standard */
      /* mgpw_log_buffer(p_log, buffer, rc, "mgpw_stdin_listener", 0); */
   }

   dup2(fd, STDIN_FILENO);

   /* mgpw_log_event(p_log, "exit", "mgpw_stdin_listener", 0); */

   return NULL;
}


void * mgpw_stdout_listener(void *pargs)
{
   int rc, clilen;
   int fd;
   int pipefd[2];
   char buffer[256], error[512];

   fd = dup(STDOUT_FILENO);
   pipe(pipefd);
   dup2(pipefd[1], STDOUT_FILENO);
   close(pipefd[1]);

   pthread_mutex_lock(&mgpw_cond_mutex);
   mgpw_cond_flag = 1;
   pthread_cond_broadcast(&mgpw_cond);
   pthread_mutex_unlock(&mgpw_cond_mutex);

   while (1) {
      fflush(stdout);
      rc = read(pipefd[0], buffer, 256);
      if (rc < 0 && errno == EINTR) {
         continue;
      }
      if (rc < 1) {
         break;
      }

      buffer[rc] = '\0';
      mgpw_tcpsrv_send(buffer, rc, 1, error);
      /* mgpw_log_buffer(p_log, buffer, rc, "mgpw_stdout_listener", 0); */
   }

   dup2(fd, STDOUT_FILENO);

   /* mgpw_log_event(p_log, "exit", "mgpw_stdout_listener", 0); */

   return NULL;
}


void * mgpw_domsrv_listener(void *pargs)
{
   int rc, clilen;

   unlink(p_tcpsrv->domsrv_name);

   p_tcpsrv->domsrv_sockfd = mgpw_domsrv_init();

   if (p_tcpsrv->domsrv_sockfd < 0) {
      sprintf(error_message, "ERROR opening socket (%d)", errno);
      mgpw_log_event(p_log, error_message, "mgpw_domsrv_init: error", 0);
      return NULL;
   }

   listen(p_tcpsrv->domsrv_sockfd, 5);

   clilen = sizeof(p_tcpsrv->domcli_addr);

   while (1) {
      p_tcpsrv->domcli_sockfd = accept(p_tcpsrv->domsrv_sockfd, (struct sockaddr *) &(p_tcpsrv->domcli_addr), &clilen);

      if (p_tcpsrv->domcli_sockfd < 0) {
         sprintf(error_message, "ERROR on accept (%d)", errno);
         mgpw_log_event(p_log, error_message, "mgpw_domsrv_init: error", 0);
         break;
      }
      rc = mgpw_domsrv_sendfd(0);
   }

   /* mgpw_log_event(p_log, "exit", "mgpw_domsrv_init", 0); */

   return NULL;
}


int mgpw_domsrv_init()
{
   int rc;

   unlink(p_tcpsrv->domsrv_name);

   p_tcpsrv->domsrv_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);

   if (p_tcpsrv->domsrv_sockfd < 0) {
      sprintf(error_message, "ERROR opening socket (%d)", errno);
      mgpw_log_event(p_log, error_message, "mgpw_domsrv_init: error", 0);
      return -1;
   }

   bzero((char *) &(p_tcpsrv->domsrv_addr), sizeof(p_tcpsrv->domsrv_addr));

   p_tcpsrv->domsrv_addr.sun_family = AF_UNIX;
   strcpy(p_tcpsrv->domsrv_addr.sun_path, p_tcpsrv->domsrv_name);

   if (bind(p_tcpsrv->domsrv_sockfd, (struct sockaddr *) &(p_tcpsrv->domsrv_addr), sizeof(p_tcpsrv->domsrv_addr)) < 0) {
      sprintf(error_message, "ERROR on binding for domain socket %s (%d)", p_tcpsrv->domsrv_name, errno);
      mgpw_log_event(p_log, error_message, "mgpw_domsrv_init: error", 0);
      close(p_tcpsrv->domsrv_sockfd);
      p_tcpsrv->domsrv_sockfd = -1;
      return -1;
   }

   return p_tcpsrv->domsrv_sockfd;
}


int mgpw_domsrv_sendfd(int sockfd)
{
   int rc, count;
   struct msghdr msg;
   char buf[CMSG_SPACE(sizeof(int))];
   struct cmsghdr *cmsg;
   struct iovec ve;
   char *st = "I";
   char buffer[32];
   ve.iov_base = st;
   ve.iov_len = 1;

   msg.msg_iov = &ve;
   msg.msg_iovlen = 1;
   msg.msg_name = NULL;
   msg.msg_namelen = 0;

   rc = recv(p_tcpsrv->domcli_sockfd, buffer, 4, 0);
   count = mgpw_get_size(buffer);

/*
{
   char buffer[256];
   sprintf(buffer, "send this socket index rc=%d; count=%d; errno=%d", rc, count, errno);
   mgpw_log_event(p_log, buffer, "mgpw_domsrv_sendfd", 0);
}
*/
   if (rc < 0) {
      return 0;
   }

   sockfd = p_tcpsrv->new_sockfd[count];

   msg.msg_control = buf;
   msg.msg_controllen = sizeof(buf);

   cmsg = CMSG_FIRSTHDR(&msg);
   cmsg->cmsg_level = SOL_SOCKET;
   cmsg->cmsg_type = SCM_RIGHTS;
   cmsg->cmsg_len = CMSG_LEN(sizeof(sockfd));

   *(int *) CMSG_DATA(cmsg) = sockfd;

   msg.msg_controllen = cmsg->cmsg_len;
   msg.msg_flags = 0;

   rc = sendmsg(p_tcpsrv->domcli_sockfd, &msg, 0);
/*
{
   char buffer[256];
   sprintf(buffer, "send this socket sockfd=%d rc=%d; errno=%d", sockfd, rc, errno);
   mgpw_log_event(p_log, buffer, "mgpw_domsrv_sendfd result", 0);
}
*/
   close(sockfd);

   return rc;
}


int mgpw_domsrv_recvfd(char *key, char *options, char *error)
{
   int sfd, n, rc, sockfd, mapstdin;
   int flag = 1;
   char *p;
   struct sockaddr_un addr;
   struct msghdr msg;
   struct iovec io;
   char ptr[1], buffer[32];
   char buf[CMSG_SPACE(sizeof(int))];
   struct cmsghdr *cm;
   pthread_attr_t attr;
   size_t stacksize, newstacksize;

   mapstdin = 0;
   mgpw_cond_flag = 0;
   pthread_attr_init(&attr);
   pthread_attr_getstacksize(&attr, &stacksize);
   newstacksize = 0x40000; /* 262144 */
   pthread_attr_setstacksize(&attr, newstacksize);

   rc = pthread_create(&(p_tcpsrv->stdout_tid), &attr, mgpw_stdout_listener, (void *) NULL);
   if (rc) {
      sprintf(error, "ERROR creating thread for mgpw_stdout_listener (%d)", errno);
      mgpw_log_event(p_log, error, "mgpw_tcpsrv_init: error", 0);
      return YDB_FAILURE;
   }
   pthread_mutex_lock(&mgpw_cond_mutex);
   while (!mgpw_cond_flag) {
      pthread_cond_wait(&mgpw_cond, &mgpw_cond_mutex);
   }
   pthread_mutex_unlock(&mgpw_cond_mutex);

   if (mapstdin) {
      mgpw_cond_flag = 0;
      pthread_attr_init(&attr);
      pthread_attr_getstacksize(&attr, &stacksize);
      newstacksize = 0x40000; /* 262144 */
      pthread_attr_setstacksize(&attr, newstacksize);
      rc = pthread_create(&(p_tcpsrv->stdout_tid), &attr, mgpw_stdin_listener, (void *) NULL);
      if (rc) {
         sprintf(error, "ERROR creating thread for mgpw_stdin_listener (%d)", errno);
         mgpw_log_event(p_log, error, "mgpw_tcpsrv_init: error", 0);
         return YDB_FAILURE;
      }
      pthread_mutex_lock(&mgpw_cond_mutex);
      while (!mgpw_cond_flag) {
         pthread_cond_wait(&mgpw_cond, &mgpw_cond_mutex);
      }
      pthread_mutex_unlock(&mgpw_cond_mutex);
   }

   p_tcpsrv->wbuffer_size = (WORK_BUFFER - 1);
   p_tcpsrv->wbuffer_datasize = 0;
   p_tcpsrv->wbuffer_offset = 0;

   p_tcpsrv->count = (int) strtol(key, NULL, 10);
   p = strstr(key, "|");
   if (!p) {
      strcpy(error, "mgpw_domsrv_recvfd: bad key");
      return YDB_FAILURE;
   }
   p ++;
   p_tcpsrv->port = (int) strtol(p, NULL, 10);
   p = strstr(key, "|||");
   if (!p) {
      strcpy(error, "mgpw_domsrv_recvfd: bad key");
      return YDB_FAILURE;
   }
   p += 3;
   strcpy(p_tcpsrv->domsrv_name, p);
   p = strstr(p_tcpsrv->domsrv_name, "|");
   if (p) {
      *p = '\0';
   }

   sfd = socket(AF_UNIX, SOCK_STREAM, 0);
   if (sfd == -1) {
      sprintf(error, "mgpw_domsrv_recvfd: bad domain socket (%d)", errno);
      mgpw_log_event(p_log, error, "mgpw_domsrv_recvfd: error", 0);
      return YDB_FAILURE;
   }

   memset(&addr, 0, sizeof(struct sockaddr_un));
   addr.sun_family = AF_UNIX;
   strcpy(addr.sun_path, p_tcpsrv->domsrv_name);

   if (connect(sfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un)) == -1) {
      sprintf(error, "mgpw_domsrv_recvfd: cannot connect to domain socket (%d)", errno);
      mgpw_log_event(p_log, error, "mgpw_domsrv_recvfd: error", 0);
      return YDB_FAILURE;
   }

   mgpw_set_size((unsigned char *) buffer, (unsigned long)  p_tcpsrv->count);
   rc = send(sfd, buffer, 4, 0);
   if (rc < 0) {
      sprintf(error, "mgpw_domsrv_recvfd: cannot send index (%d)", errno);
      mgpw_log_event(p_log, error, "mgpw_domsrv_recvfd: error", 0);
      return YDB_FAILURE;
   }
   io.iov_base = ptr;
   io.iov_len = 1;
   msg.msg_name = 0;
   msg.msg_namelen = 0;
   msg.msg_iov = &io;
   msg.msg_iovlen = 1;
   msg.msg_control = buf;
   msg.msg_controllen = sizeof(buf);

   for (n = 0; n < 10; n ++) {
      rc = recvmsg(sfd, &msg, 0);
      if (rc < 0 && errno == EINTR) {
         sleep(1);
         continue;
      }
      if (rc >= 0)
         break;
   }
   if (rc < 0) {
      sprintf(error, "mgpw_domsrv_recvfd: cannot read from domain socket (%d)", errno);
      mgpw_log_event(p_log, error, "mgpw_domsrv_recvfd: error", 0);
      return YDB_FAILURE;
   }

   cm = CMSG_FIRSTHDR(&msg);
   if (cm->cmsg_type != SCM_RIGHTS) {
      sprintf(error, "mgpw_domsrv_recvfd: unknown mesasge type from domain socket (%d)", errno);
      mgpw_log_event(p_log, error, "mgpw_domsrv_recvfd: error", 0);
      return YDB_FAILURE;
   }

   p_tcpsrv->cli_sockfd = *(int *) CMSG_DATA(cm);

   rc = setsockopt(p_tcpsrv->cli_sockfd, IPPROTO_TCP, TCP_NODELAY, (const char *) &flag, sizeof(int));

   close(sfd);

/*
{
   char buffer[256];
   sprintf(buffer, "send this socket sockfd=%d rc=%d; errno=%d", p_tcpsrv->cli_sockfd, rc, errno);
   mgpw_log_event(p_log, buffer, "mgpw_domsrv_recvfd result: should have socket now 1", 0);
}
*/

/* experiental code */
/*
#if 0
   if (1) {
      strcpy(p_ydb_so->libdir, "/usr/local/lib/yottadb/r130");
      ydb_load_library(p_ydb_so);
   
      if (p_ydb_so->p_library) {
         rc = p_ydb_so->p_ydb_init();
      }
   }
#endif
*/

   return YDB_OK;
}


int mgpw_tcpsrv_init(int port, char *options, char *error)
{
   int rc, n, sockfd, newsockfd, portno, clilen;
   const int on = 1;
   char buffer[256];
   pthread_attr_t attr;
   size_t stacksize, newstacksize;
/*
   mgpw_log_event(p_log, "initialise", "mgpw_tcpsrv_init", 0);
*/
   for (n = 0; n < MGPW_MAX_CLIFD; n ++) {
      p_tcpsrv->new_sockfd[n] = 0;
   }

   p_tcpsrv->count = 0;
   p_tcpsrv->port = port;
   p_tcpsrv->srv_sockfd = socket(AF_INET, SOCK_STREAM, 0);

   if (p_tcpsrv->srv_sockfd < 0) {
      sprintf(error, "ERROR opening socket (%d)", errno);
      mgpw_log_event(p_log, error, "mgpw_tcpsrv_init: error", 0);
      return YDB_FAILURE;
   }

   setsockopt(p_tcpsrv->srv_sockfd, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on));

   bzero((char *) &(p_tcpsrv->srv_addr), sizeof(p_tcpsrv->srv_addr));

   p_tcpsrv->srv_addr.sin_family = AF_INET;
   p_tcpsrv->srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
   p_tcpsrv->srv_addr.sin_port = htons(port);

   if (bind(p_tcpsrv->srv_sockfd, (struct sockaddr *) &(p_tcpsrv->srv_addr), sizeof(p_tcpsrv->srv_addr)) < 0) {
      sprintf(error, "ERROR on binding (%d)", errno);
      mgpw_log_event(p_log, error, "mgpw_tcpsrv_init: error", 0);
      return YDB_FAILURE;
   }
   if (listen(p_tcpsrv->srv_sockfd, 5) < 0) {
      sprintf(error, "ERROR on listen (%d)", errno);
      mgpw_log_event(p_log, error, "mgpw_tcpsrv_init: error", 0);
      return YDB_FAILURE;
   }

   sprintf(p_tcpsrv->domsrv_name, "/tmp/mg_pwind%ld.str", (unsigned long) getpid());
/*
{
   char buffer[256];
   sprintf(buffer, "sfd: srv_sockfd=%d; errno=%d", p_tcpsrv->srv_sockfd, errno);
   mgpw_log_event(p_log, p_tcpsrv->domsrv_name, "mgpw_tcpsrv_init", 0);
}
*/
   pthread_attr_init(&attr);
   pthread_attr_getstacksize(&attr, &stacksize);
   newstacksize = 0x40000; /* 262144 */
   pthread_attr_setstacksize(&attr, newstacksize);
   rc = pthread_create(&(p_tcpsrv->domsrv_tid), &attr, mgpw_domsrv_listener, (void *) NULL);
   if (rc) {
      sprintf(error, "ERROR creating thread for mgpw_domsrv_listener (%d)", errno);
      mgpw_log_event(p_log, error, "mgpw_tcpsrv_init: error", 0);
      return YDB_FAILURE;
   }

   return YDB_OK;
}


int mgpw_tcpsrv_accept(char *key, char *error)
{
   int rc, clilen, count, smax, len;
   fd_set socket_set;
   struct timeval timeout;

   error[0] = '\0';
   count = -1;
   if (key[0]) {
/*
      mgpw_log_event(p_log, key, "mgpw_tcpsrv_accept: existing key", 0);
*/
      count = (int) strtol(key, NULL, 10);
      if (count >= MGPW_MAX_CLIFD) {
         count = -1;
      }
   }
   if (count == -1) {
      count = p_tcpsrv->count;
      p_tcpsrv->count ++;
      if (p_tcpsrv->count >= MGPW_MAX_CLIFD) {
         p_tcpsrv->count = 0;
      }
      sprintf(key, "%d|%d|||%s|", count, p_tcpsrv->port, p_tcpsrv->domsrv_name);
/*
      mgpw_log_event(p_log, key, "mgpw_tcpsrv_accept: new key", 0);
*/
   }

   smax = p_tcpsrv->srv_sockfd;

   rc = YDB_OK;
   while (1) {
      FD_ZERO(&socket_set);
      FD_SET(p_tcpsrv->srv_sockfd, &socket_set);

      timeout.tv_sec = 10;
      timeout.tv_usec = 0;

      rc = select(smax + 1, &socket_set, NULL, NULL, &timeout);
/*
{
   char buffer[256];
   sprintf(buffer, "rc=%d; errno=%d", rc, errno);
   mgpw_log_event(p_log, buffer, "mgpw_tcpsrv_accept: select", 0);
}
*/
      if (rc == 0) {
         strcpy(error, "<TIMEOUT>");
         rc = YDB_FAILURE;
         break;
      }
      else if (rc < 0 && errno == EINTR) {
         strcpy(error, "<EINTR>");
         rc = YDB_FAILURE;
         break;
      }
      else if (rc > 0) {
         if (FD_ISSET(p_tcpsrv->srv_sockfd, &socket_set)) {
            clilen = sizeof(p_tcpsrv->cli_addr);
            p_tcpsrv->new_sockfd[count] = accept(p_tcpsrv->srv_sockfd, (struct sockaddr *) &(p_tcpsrv->cli_addr), &clilen);
            if (p_tcpsrv->new_sockfd[count] > 0) {
               len = strlen(key);
               inet_ntop(AF_INET, (struct sockaddr *) &(p_tcpsrv->cli_addr), key + len, 32);
               rc = YDB_OK;
               break;
            }
         }
      }
   }

/*
{
   char buffer[256];
   sprintf(buffer, "rc=%d; port=%d count=%d; p_tcpsrv->new_sockfd[count]=%d; p_tcpsrv->srv_sockfd=%d; errno=%d", rc, p_tcpsrv->port, count, p_tcpsrv->new_sockfd[count], p_tcpsrv->srv_sockfd, errno);
   mgpw_log_event(p_log, buffer, "mgpw_tcpsrv_accept", 0);
}
*/

   return rc;
}


int mgpw_tcpsrv_send(char *data, int len, int flush, char *error)
{
   int rc;

   rc = send(p_tcpsrv->cli_sockfd, data, len, 0);

   if (rc == 0) {
      strcpy(error, "<EOF>");
   }
   else if (rc < 0) {
      sprintf(error, "mgpw_tcpsrv_send (%d)", errno);
   }
/*
{
   char buffer[256];
   sprintf(buffer, "rc=%d; p_tcpsrv->cli_sockfd=%d; errno=%d", rc, p_tcpsrv->cli_sockfd, errno);
   mgpw_log_event(p_log, buffer, "mgpw_tcpsrv_send", 0);
}
*/
   return rc;
}


int mgpw_tcpsrv_recv(char *data, int dsize, int len, int timeout, char *error)
{
   int rc, eno, timed_out;
   unsigned int avail, got, get;
   fd_set rset, eset;
   struct timeval tval;

/*
{
   char buffer[256];
   sprintf(buffer, "START: dsize=%d; len=%d; timeout=%d; wbuffer_datasize=%d; wbuffer_offset=%d", dsize, len, timeout, p_tcpsrv->wbuffer_datasize, p_tcpsrv->wbuffer_offset);
   mgpw_log_event(p_log, buffer, "mgpw_tcpsrv_recv", 0);
}
*/
   timed_out = 0;
   data[0] = '\0';

   if (len > 0)
      get = len;
   else
      get = dsize;
   got = 0;
   while (got < get) {
      avail = (p_tcpsrv->wbuffer_datasize - p_tcpsrv->wbuffer_offset);
      if (avail >= get) { /* all we need is already in buffer */
         memcpy((void *) (data + got), (void *) (p_tcpsrv->wbuffer + p_tcpsrv->wbuffer_offset), (size_t) get);
         got += get;
         p_tcpsrv->wbuffer_offset += get;
         get = 0;
         rc = got;
/*
{
   char buffer[256];
   sprintf(buffer, "FULL BUFFER READ: dsize=%d; len=%d; wbuffer_datasize=%d; wbuffer_offset=%d; got=%d; get=%d; avail=%d", dsize, len, p_tcpsrv->wbuffer_datasize, p_tcpsrv->wbuffer_offset, got, get, avail);
   mgpw_log_event(p_log, buffer, "mgpw_tcpsrv_recv", 0);
}
*/

         break;
      }
      if (avail > 0) { /* get what we can from the buffer */
         memcpy((void *) (data + got), (void *) (p_tcpsrv->wbuffer + p_tcpsrv->wbuffer_offset), (size_t) avail);
         got += avail;
         p_tcpsrv->wbuffer_offset += avail;
         get -= avail;
/*
{
   char buffer[256];
   sprintf(buffer, "PART BUFFER READ: dsize=%d; len=%d; wbuffer_datasize=%d; wbuffer_offset=%d; got=%d; get=%d; avail=%d", dsize, len, p_tcpsrv->wbuffer_datasize, p_tcpsrv->wbuffer_offset, got, get, avail);
   mgpw_log_event(p_log, buffer, "mgpw_tcpsrv_recv", 0);
}
*/
         if (len == 0) {
            rc = got;
            break;
         }
      }
      p_tcpsrv->wbuffer_offset = 0;
      p_tcpsrv->wbuffer_datasize = 0;
      eno = 0;
      while (eno < 5) {
         if (timeout > 0) {
            FD_ZERO(&rset);
            FD_ZERO(&eset);
            FD_SET(p_tcpsrv->cli_sockfd, &rset);
            FD_SET(p_tcpsrv->cli_sockfd, &eset);

            tval.tv_sec = timeout;
            tval.tv_usec = 0;

            rc = select(p_tcpsrv->cli_sockfd + 1, &rset, NULL, &eset, &tval);
            if (rc < 0 && errno == EINTR) {
               eno ++;
               continue;
            }
            else if (rc == 0) {
               timed_out = 1;
               break;
            }
         }
         rc = recv(p_tcpsrv->cli_sockfd, p_tcpsrv->wbuffer, p_tcpsrv->wbuffer_size, 0);
         if (rc < 0 && errno == EINTR) {
            eno ++;
            continue;
         }
         break;
      }
      if (rc < 1) {
         break;
      }
      p_tcpsrv->wbuffer_datasize = (unsigned int) rc;
/*
{
   char buffer[256];
   sprintf(buffer, "recv: rc=%d; eno=%d; errno=%d;", rc, eno, errno);
   mgpw_log_buffer(p_log, p_tcpsrv->wbuffer, rc, buffer, 0);
}
*/

   }

   if (rc > 0) {
      data[rc] = '\0';
   }
   else if (rc == 0) {
      if (timed_out)
         strcpy(error, "<TIMEOUT>");
      else
         strcpy(error, "<EOF>");
   }
   else if (rc < 0) {
      sprintf(error, "mgpw_tcpsrv_recv (%d)", errno);
   }
/*
{
   char buffer[512];
   sprintf(buffer, "rc=%d; p_tcpsrv->cli_sockfd=%d; errno=%d", rc, p_tcpsrv->cli_sockfd, errno);
   mgpw_log_event(p_log, buffer, "mgpw_tcpsrv_recv a", 0);
   mgpw_log_event(p_log, data, "mgpw_tcpsrv_recv b", 0);
}
*/
   return rc;
}


int mgpw_tcpsrv_recv_message(char *data, int dsize, int *len, int *cmnd, int timeout, char *error)
{
   int rc;

   rc = mgpw_tcpsrv_recv(data, dsize, 5, timeout, error);
   if (rc != 5) {
      rc = YDB_FAILURE;
      return rc;
   }

   *len = (int) mgpw_get_size((unsigned char *) data) - 5;
   *cmnd = (int) data[4];

   if (*len > 0) {
      rc = mgpw_tcpsrv_recv(data, dsize, *len, timeout, error);
   }

/* experiental code */
#if 0

   if (p_ydb_so->p_library && *cmnd == 12) { /* 12 == $get() */
      int n, lenx, type, sort;
      char *p;
      ydb_buffer_t global;
      ydb_buffer_t key[32];
      ydb_buffer_t datax;

      p = (data + 10);
      for (n = 0; n < 32; n ++) {
         lenx = (int) mgpw_get_size((unsigned char *) p);
         p += 4;
         sort = (int) (((unsigned char) (*p)) / 20);
         type = (int) (((unsigned char) (*p)) % 20);
         if (sort == 9) {
            break;
         }
         p ++;
         if (n == 0) {
            global.buf_addr = p;
            global.len_used = lenx;
            global.len_alloc = lenx + 1;
         }
         else {
            key[n - 1].buf_addr = p;
            key[n - 1].len_used = lenx;
            key[n - 1].len_alloc = lenx + 1;
         }
         p += lenx;
/*
         {
            char buffer[256];
            sprintf(buffer, "input cmnd=%d; n=%d; sort=%d, type=%d; lenx=%d;", *cmnd, n, sort, type, lenx);
            mgpw_log_buffer(p_log, data, *len, buffer, 0);
         }
*/
      }

      datax.buf_addr = (char *) (p_tcpsrv->wbuffer + 5);
      datax.len_alloc = (unsigned int) (p_tcpsrv->wbuffer_size - 5);
      datax.len_used = 0;

      rc = p_ydb_so->p_ydb_get_s(&global, n - 1, &key[0], &datax);

      mgpw_set_size((unsigned char *) p_tcpsrv->wbuffer, (unsigned long) datax.len_used);
      sort = 1;
      type = 1;
      p_tcpsrv->wbuffer[4] = (unsigned char) ((sort * 20) + type);
/*
      {
         char buffer[256];
         sprintf(buffer, "result: p_ydb_get_s=%d; len=%d; cmnd=%d", rc, datax.len_used, *cmnd);
         mgpw_log_buffer(p_log, p_tcpsrv->wbuffer, datax.len_used + 5, buffer, 0);
      }
*/
      mgpw_tcpsrv_send(p_tcpsrv->wbuffer, datax.len_used + 5, 1, error);
      *cmnd = 0;
   }

#endif

   return rc;
}


int mgpw_tcpsrv_close(char *key)
{
   int len;

   len = (int) strlen(key);

   if (len == 0) { /* must be a client */
      close(p_tcpsrv->cli_sockfd);
   }
   else { /* the server */
      close(p_tcpsrv->srv_sockfd);
      close(p_tcpsrv->domsrv_sockfd);
   }

   return YDB_OK;
}

#endif /* #if !defined(_WIN32) */

