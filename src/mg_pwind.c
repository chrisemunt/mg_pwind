/*
   ----------------------------------------------------------------------------
   | mg_pwind.so|dll                                                          |
   | Description: Access to DSO functions from YottaDB                        |
   | Author:      Chris Munt cmunt@mgateway.com                               |
   |                         chris.e.munt@gmail.com                           |
   | Copyright (c) 2020-2021 M/Gateway Developments Ltd,                      |
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
   Introduce experimemtal network I/O layer. 

*/


#include "mg_pwind.h"

#if !defined(_WIN32)
extern int errno;
#endif

static DBXCRYPTSO crypt_so       = {0, {0}, {0}, NULL, NULL};
static DBXCRYPTSO *p_crypt_so    = &crypt_so;

static DBXYDBSO ydb_so           = {0, {0}, {0}, {0}, {0}, NULL, NULL};
static DBXYDBSO *p_ydb_so        = &ydb_so;

static DBXTCPSRV  tcpsrv         = {0, 0};
static DBXTCPSRV  *p_tcpsrv      = &tcpsrv;

static DBXLOG     pwindlog       = {"/tmp/mg_pwind.log", {0}, 0};
static DBXLOG     *p_log         = &pwindlog;

static char error_message[512]   = {0};
static int  error_code = 0;

MG_MALLOC            dbx_ext_malloc = NULL;
MG_REALLOC           dbx_ext_realloc = NULL;
MG_FREE              dbx_ext_free = NULL;

#if defined(_WIN32)
CRITICAL_SECTION  dbx_global_mutex;
#else
pthread_mutex_t   dbx_global_mutex  = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t   dbx_cond_mutex    = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t    dbx_cond          = PTHREAD_COND_INITIALIZER;
static int        dbx_cond_flag     = 0;
#endif

int cmtxxx = 1;

#if defined(_WIN32)
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
   switch (fdwReason)
   { 
      case DLL_PROCESS_ATTACH:
         mg_init_critical_section((void *) &dbx_global_mutex);
         break;
      case DLL_THREAD_ATTACH:
         break;
      case DLL_THREAD_DETACH:
         break;
      case DLL_PROCESS_DETACH:
         mg_delete_critical_section((void *) &dbx_global_mutex);
         break;
   }
   return TRUE;
}
#endif /* #if defined(_WIN32) */


DBX_EXTFUN(int) mg_version(int count, ydb_string_t *out)
{
   sprintf((char *) out->address, "mg_pwind:%s", DBX_VERSION);
   out->length = (int) strlen(out->address);

   return YDB_OK;
}


DBX_EXTFUN(int) mg_crypt_library(int count, ydb_string_t *in)
{
   strcpy(p_crypt_so->libnam, in->address);
   return YDB_OK;
}


DBX_EXTFUN(int) mg_ssl_version(int count, ydb_string_t *out, ydb_string_t *error)
{
   DBX_CRYPT_LOAD(error);

   strcpy((char *) out->address, p_crypt_so->p_OpenSSL_version(0));
   out->length = (int) strlen(out->address);

   return YDB_OK;
}


DBX_EXTFUN(int) mg_sha1(int count, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error)
{
   int mac_len, len;
   char mac[1024];

   DBX_CRYPT_LOAD(error);

   memset(mac, 0, 1024);
   p_crypt_so->p_SHA1(in->address, in->length, mac);
   mac_len = 20;

   if (flags == 1) {
      len = mg_b64_encode((char *) mac, mac_len, out->address, 0);
      out->address[len] = '\0';
      out->length = len;
   }
   else if (flags == 2) {
      len = mg_hex_encode((char *) mac, mac_len, out->address);
      out->address[len] = '\0';
      out->length = len;
   }
   else {
      memcpy((void *) out->address, (void *) mac, (size_t) mac_len);
      out->length = mac_len;
   }

   return YDB_OK;
}


DBX_EXTFUN(int) mg_sha256(int count, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error)
{
   int mac_len, len;
   char mac[1024];

   DBX_CRYPT_LOAD(error);

   memset(mac, 0, 1024);
   p_crypt_so->p_SHA256(in->address, in->length, mac);
   mac_len = 32;

   if (flags == 1) {
      len = mg_b64_encode((char *) mac, mac_len, out->address, 0);
      out->address[len] = '\0';
      out->length = len;
   }
   else if (flags == 2) {
      len = mg_hex_encode((char *) mac, mac_len, out->address);
      out->address[len] = '\0';
      out->length = len;
   }
   else {
      memcpy((void *) out->address, (void *) mac, (size_t) mac_len);
      out->length = mac_len;
   }

   return YDB_OK;
}


DBX_EXTFUN(int) mg_sha512(int count, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error)
{
   int mac_len, len;
   char mac[1024];

   DBX_CRYPT_LOAD(error);

   memset(mac, 0, 1024);
   p_crypt_so->p_SHA512(in->address, in->length, mac);
   mac_len = 64;

   if (flags == 1) {
      len = mg_b64_encode((char *) mac, mac_len, out->address, 0);
      out->address[len] = '\0';
      out->length = len;
   }
   else if (flags == 2) {
      len = mg_hex_encode((char *) mac, mac_len, out->address);
      out->address[len] = '\0';
      out->length = len;
   }
   else {
      memcpy((void *) out->address, (void *) mac, (size_t) mac_len);
      out->length = mac_len;
   }

   return YDB_OK;
}


DBX_EXTFUN(int) mg_md5(int count, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error)
{
   int mac_len, len;
   char mac[1024];

   DBX_CRYPT_LOAD(error);

   memset(mac, 0, 1024);
   p_crypt_so->p_MD5(in->address, in->length, mac);
   mac_len = 16;

   if (flags == 1) {
      len = mg_b64_encode((char *) mac, mac_len, out->address, 0);
      out->address[len] = '\0';
      out->length = len;
   }
   else if (flags == 2) {
      len = mg_hex_encode((char *) mac, mac_len, out->address);
      out->address[len] = '\0';
      out->length = len;
   }
   else {
      memcpy((void *) out->address, (void *) mac, (size_t) mac_len);
      out->length = mac_len;
   }

   return YDB_OK;
}


DBX_EXTFUN(int) mg_hmac_sha1(int count, ydb_string_t *key, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error)
{
   int mac_len, len;
   char mac[1024];

   DBX_CRYPT_LOAD(error);

   memset(mac, 0, 1024);
   p_crypt_so->p_HMAC(p_crypt_so->p_EVP_sha1(), key->address, key->length, in->address, in->length, mac, &mac_len);

   if (flags == 1) {
      len = mg_b64_encode((char *) mac, mac_len, out->address, 0);
      out->address[len] = '\0';
      out->length = len;
   }
   else if (flags == 2) {
      len = mg_hex_encode((char *) mac, mac_len, out->address);
      out->address[len] = '\0';
      out->length = len;
   }
   else {
      memcpy((void *) out->address, (void *) mac, (size_t) mac_len);
      out->length = mac_len;
   }

   return YDB_OK;
}


DBX_EXTFUN(int) mg_hmac_sha256(int count, ydb_string_t *key, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error)
{
   int mac_len, len;
   char mac[1024];

   DBX_CRYPT_LOAD(error);

   memset(mac, 0, 1024);
   p_crypt_so->p_HMAC(p_crypt_so->p_EVP_sha256(), key->address, key->length, in->address, in->length, mac, &mac_len);

   if (flags == 1) {
      len = mg_b64_encode((char *) mac, mac_len, out->address, 0);
      out->address[len] = '\0';
      out->length = len;
   }
   else if (flags == 2) {
      len = mg_hex_encode((char *) mac, mac_len, out->address);
      out->address[len] = '\0';
      out->length = len;
   }
   else {
      memcpy((void *) out->address, (void *) mac, (size_t) mac_len);
      out->length = mac_len;
   }

   return YDB_OK;
}


DBX_EXTFUN(int) mg_hmac_sha512(int count, ydb_string_t *key, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error)
{
   int mac_len, len;
   char mac[1024];

   DBX_CRYPT_LOAD(error);

   memset(mac, 0, 1024);
   p_crypt_so->p_HMAC(p_crypt_so->p_EVP_sha512(), key->address, key->length, in->address, in->length, mac, &mac_len);

   if (flags == 1) {
      len = mg_b64_encode((char *) mac, mac_len, out->address, 0);
      out->address[len] = '\0';
      out->length = len;
   }
   else if (flags == 2) {
      len = mg_hex_encode((char *) mac, mac_len, out->address);
      out->address[len] = '\0';
      out->length = len;
   }
   else {
      memcpy((void *) out->address, (void *) mac, (size_t) mac_len);
      out->length = mac_len;
   }

   return YDB_OK;
}


DBX_EXTFUN(int) mg_hmac_md5(int count, ydb_string_t *key, ydb_string_t *in, ydb_int_t flags, ydb_string_t *out, ydb_string_t *error)
{
   int mac_len, len;
   char mac[1024];

   DBX_CRYPT_LOAD(error);

   memset(mac, 0, 1024);
   p_crypt_so->p_HMAC(p_crypt_so->p_EVP_md5(), key->address, key->length, in->address, in->length, mac, &mac_len);

   if (flags == 1) {
      len = mg_b64_encode((char *) mac, mac_len, out->address, 0);
      out->address[len] = '\0';
      out->length = len;
   }
   else if (flags == 2) {
      len = mg_hex_encode((char *) mac, mac_len, out->address);
      out->address[len] = '\0';
      out->length = len;
   }
   else {
      memcpy((void *) out->address, (void *) mac, (size_t) mac_len);
      out->length = mac_len;
   }

   return YDB_OK;
}


DBX_EXTFUN(int) mg_encode_b64(int count, ydb_string_t *in, ydb_string_t *out)
{
   int len;

   len = mg_b64_encode((char *) in->address, in->length, out->address, 0);
   out->address[len] = '\0';
   out->length = len;

   return YDB_OK;
}


DBX_EXTFUN(int) mg_decode_b64(int count, ydb_string_t *in, ydb_string_t *out)
{
   int len;

   len = mg_b64_decode((char *) in->address, in->length, out->address);
   out->address[len] = '\0';
   out->length = len;

   return YDB_OK;
}


DBX_EXTFUN(int) mg_crc32(int count, ydb_string_t *in, ydb_uint_t *out)
{
   *out = (ydb_uint_t) mg_crc32_checksum(in->address, (size_t) in->length);

   return YDB_OK;
}


/* v1.2.2 */
#if !defined(_WIN32)
DBX_EXTFUN(int) mg_tcp_options(int count, ydb_string_t *options, ydb_string_t *error)
{
   return YDB_OK;
}


DBX_EXTFUN(int) mg_tcpserver_init(int count, ydb_int_t port, ydb_string_t *options, ydb_string_t *error)
{
   int rc;

   error->address[0] = '\0';
   error->length = 0;

   rc = mg_tcpsrv_init((int) port, options->address, error->address);
   if (rc != YDB_OK) {
      error->length = (unsigned long) strlen(error->address);
   }

   return YDB_OK;
}


DBX_EXTFUN(int) mg_tcpserver_accept(int count, ydb_string_t *key, ydb_string_t *error)
{
   int rc;

   error->address[0] = '\0';
   error->length = 0;
   if (key->length == 0) {
      key->address[0] = '\0';
   }
   rc = mg_tcpsrv_accept(key->address, error->address);
   key->length = (unsigned long) strlen(key->address);
   if (rc != YDB_OK) {
      error->length = (unsigned long) strlen(error->address);
   }

   return YDB_OK;
}


DBX_EXTFUN(int) mg_tcpserver_close(int count, ydb_string_t *key)
{
   int rc;

   rc = mg_tcpsrv_close(key->address);

   return rc;
}


DBX_EXTFUN(int) mg_tcpchild_init(int count, ydb_string_t *key, ydb_string_t *options, ydb_string_t *error)
{
   int rc;

   error->address[0] = '\0';
   error->length = 0;

   rc = mg_domsrv_recvfd(key->address, options->address, error->address);
   key->length = (unsigned long) strlen(key->address);
   if (rc != YDB_OK) {
      error->length = (unsigned long) strlen(error->address);
   }

   return YDB_OK;
}


DBX_EXTFUN(int) mg_tcpchild_send(int count, ydb_string_t *data, ydb_int_t flush, ydb_string_t *error)
{
   int rc;

   error->address[0] = '\0';
   error->length = 0;

   rc = mg_tcpsrv_send(data->address, (int) data->length, (int) flush, (char *) error->address);
   if (error->address[0]) {
      error->length = (unsigned long) strlen(error->address);
   }

   return YDB_OK;
}


DBX_EXTFUN(int) mg_tcpchild_recv(int count, ydb_string_t *data, ydb_int_t len, ydb_int_t timeout, ydb_string_t *error)
{
   int rc;
   int dsize;

   error->address[0] = '\0';
   error->length = 0;
   data->address[0] = '\0';
   data->length = 0;
   dsize = (WORK_BUFFER - 1);

   rc = mg_tcpsrv_recv(data->address, (int) dsize, (int) len, (int) timeout, error->address);
   if (error->address[0]) {
      error->length = (unsigned long) strlen(error->address);
   }
   if (rc >= 0) {
      data->length = rc;
   }

   return YDB_OK;
}


DBX_EXTFUN(int) mg_tcpchild_recv_ascii(int count, ydb_int_t *data, ydb_int_t timeout, ydb_string_t *error)
{
   int rc;
   char buffer[8];

   error->address[0] = '\0';
   error->length = 0;

   rc = mg_tcpsrv_recv(buffer, (int) 7, (int) 1, (int) timeout, error->address);
   if (error->address[0]) {
      error->length = (unsigned long) strlen(error->address);
   }
   if (rc >= 0) {
      *data = (ydb_int_t) buffer[0];
   }

   return YDB_OK;
}


DBX_EXTFUN(int) mg_tcpchild_recv_message(int count, ydb_string_t *data, ydb_int_t *len, ydb_int_t *cmnd, ydb_int_t timeout, ydb_string_t *error)
{
   int rc;
   int dsize;

   error->address[0] = '\0';
   error->length = 0;
   data->address[0] = '\0';
   data->length = 0;
   dsize = (WORK_BUFFER - 1);

   rc = mg_tcpsrv_recv_message(data->address, (int) dsize, (int *) len, (int *) cmnd, (int) timeout, error->address);
   if (error->address[0]) {
      error->length = (unsigned long) strlen(error->address);
   }
   if (rc >= 0) {
      data->length = rc;
   }

   return YDB_OK;
}


DBX_EXTFUN(int) mg_tcpchild_close(int count)
{
   int rc;

   rc = mg_tcpsrv_close("");

   return rc;
}
#endif /* #if !defined(_WIN32) */


int crypt_load_library(DBXCRYPTSO *p_crypt_so)
{
   int n, result;
   char primlib[DBX_ERROR_SIZE], primerr[DBX_ERROR_SIZE];
   char fun[64];
   char *libnam[16];

   strcpy(p_crypt_so->dbname, "Crypto");

   n = 0;
   if (p_crypt_so->libnam[0]) {
      libnam[n ++] = (char *) p_crypt_so->libnam;
   }
   else {
#if defined(_WIN32)
      libnam[n ++] = (char *) DBX_CRYPT_DLL;
#else
#if defined(MACOSX)
      libnam[n ++] = (char *) DBX_CRYPT_DYLIB;
      libnam[n ++] = (char *) DBX_CRYPT_SO;
#else
      libnam[n ++] = (char *) DBX_CRYPT_SO;
      libnam[n ++] = (char *) DBX_CRYPT_DYLIB;
#endif
#endif
   }

   libnam[n ++] = NULL;

   for (n = 0; libnam[n]; n ++) {

      p_crypt_so->p_library = mg_dso_load(libnam[n]);
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
         if (lpMsgBuf && len1 > 0 && (DBX_ERROR_SIZE - len2) > 30) {
            strncpy(primerr, (const char *) lpMsgBuf, DBX_ERROR_SIZE - 1);
            p = strstr(primerr, "\r\n");
            if (p)
               *p = '\0';
            len1 = (DBX_ERROR_SIZE - (len2 + 10));
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
            strncpy(primerr, p, DBX_ERROR_SIZE - 1);
            primerr[DBX_ERROR_SIZE - 1] = '\0';
            len1 = (DBX_ERROR_SIZE - (len2 + 10));
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
      goto crypt_load_library;
   }

   strcpy(fun, "OpenSSL_version");
   p_crypt_so->p_OpenSSL_version = (const char * (*) (int)) mg_dso_sym(p_crypt_so->p_library, (char *) fun);
   if (!p_crypt_so->p_OpenSSL_version) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_crypt_so->dbname, p_crypt_so->libnam, fun);
      goto crypt_load_library;
   }

   strcpy(fun, "HMAC");
   p_crypt_so->p_HMAC = (unsigned char * (*) (const EVP_MD *, const void *, int, const unsigned char *, int, unsigned char *, unsigned int *)) mg_dso_sym(p_crypt_so->p_library, (char *) fun);
   if (!p_crypt_so->p_HMAC) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_crypt_so->dbname, p_crypt_so->libnam, fun);
      goto crypt_load_library;
   }
   strcpy(fun, "EVP_sha1");
   p_crypt_so->p_EVP_sha1 = (const EVP_MD * (*) (void)) mg_dso_sym(p_crypt_so->p_library, (char *) fun);
   if (!p_crypt_so->p_EVP_sha1) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_crypt_so->dbname, p_crypt_so->libnam, fun);
      goto crypt_load_library;
   }
   strcpy(fun, "EVP_sha256");
   p_crypt_so->p_EVP_sha256 = (const EVP_MD * (*) (void)) mg_dso_sym(p_crypt_so->p_library, (char *) fun);
   if (!p_crypt_so->p_EVP_sha256) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_crypt_so->dbname, p_crypt_so->libnam, fun);
      goto crypt_load_library;
   }
   strcpy(fun, "EVP_sha512");
   p_crypt_so->p_EVP_sha512 = (const EVP_MD * (*) (void)) mg_dso_sym(p_crypt_so->p_library, (char *) fun);
   if (!p_crypt_so->p_EVP_sha512) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_crypt_so->dbname, p_crypt_so->libnam, fun);
      goto crypt_load_library;
   }

   strcpy(fun, "EVP_md5");
   p_crypt_so->p_EVP_md5 = (const EVP_MD * (*) (void)) mg_dso_sym(p_crypt_so->p_library, (char *) fun);
   if (!p_crypt_so->p_EVP_md5) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_crypt_so->dbname, p_crypt_so->libnam, fun);
      goto crypt_load_library;
   }

   strcpy(fun, "SHA1");
   p_crypt_so->p_SHA1 = (unsigned char * (*) (const unsigned char *, unsigned long, unsigned char *)) mg_dso_sym(p_crypt_so->p_library, (char *) fun);
   if (!p_crypt_so->p_SHA1) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_crypt_so->dbname, p_crypt_so->libnam, fun);
      goto crypt_load_library;
   }
   strcpy(fun, "SHA256");
   p_crypt_so->p_SHA256 = (unsigned char * (*) (const unsigned char *, unsigned long, unsigned char *)) mg_dso_sym(p_crypt_so->p_library, (char *) fun);
   if (!p_crypt_so->p_SHA256) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_crypt_so->dbname, p_crypt_so->libnam, fun);
      goto crypt_load_library;
   }
   strcpy(fun, "SHA512");
   p_crypt_so->p_SHA512 = (unsigned char * (*) (const unsigned char *, unsigned long, unsigned char *)) mg_dso_sym(p_crypt_so->p_library, (char *) fun);
   if (!p_crypt_so->p_SHA512) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_crypt_so->dbname, p_crypt_so->libnam, fun);
      goto crypt_load_library;
   }
   strcpy(fun, "MD5");
   p_crypt_so->p_MD5 = (unsigned char * (*) (const unsigned char *, unsigned long, unsigned char *)) mg_dso_sym(p_crypt_so->p_library, (char *) fun);
   if (!p_crypt_so->p_MD5) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_crypt_so->dbname, p_crypt_so->libnam, fun);
      goto crypt_load_library;
   }

   p_crypt_so->loaded = 1;

crypt_load_library:

   if (error_message[0]) {
      p_crypt_so->loaded = 0;
      error_code = 1009;
      result = YDB_FAILURE;
      return result;
   }

   return YDB_OK;
}


int ydb_load_library(DBXYDBSO *p_ydb_so)
{
   int n, len, result;
   char primlib[DBX_ERROR_SIZE], primerr[DBX_ERROR_SIZE];
   char fun[64];
   char *libnam[16];

   strcpy(p_ydb_so->funprfx, "ydb");
   strcpy(p_ydb_so->dbname, "YottaDB");

   len = (int) strlen(p_ydb_so->libdir);
   if (p_ydb_so->libdir[len - 1] != '/' && p_ydb_so->libdir[len - 1] != '\\') {
      p_ydb_so->libdir[len] = '/';
      len ++;
   }

   n = 0;
#if defined(_WIN32)
   libnam[n ++] = (char *) DBX_YDB_DLL;
#else
#if defined(MACOSX)
   libnam[n ++] = (char *) DBX_YDB_DYLIB;
   libnam[n ++] = (char *) DBX_YDB_SO;
#else
   libnam[n ++] = (char *) DBX_YDB_SO;
   libnam[n ++] = (char *) DBX_YDB_DYLIB;
#endif
#endif

   libnam[n ++] = NULL;
   strcpy(p_ydb_so->libnam, p_ydb_so->libdir);
   len = (int) strlen(p_ydb_so->libnam);

   for (n = 0; libnam[n]; n ++) {
      strcpy(p_ydb_so->libnam + len, libnam[n]);
      if (!n) {
         strcpy(primlib, p_ydb_so->libnam);
      }

      p_ydb_so->p_library = mg_dso_load(p_ydb_so->libnam);
      if (p_ydb_so->p_library) {
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
         sprintf(error_message, "Error loading %s Library: %s; Error Code : %ld",  p_ydb_so->dbname, primlib, errorcode);
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
         if (lpMsgBuf && len1 > 0 && (DBX_ERROR_SIZE - len2) > 30) {
            strncpy(primerr, (const char *) lpMsgBuf, DBX_ERROR_SIZE - 1);
            p = strstr(primerr, "\r\n");
            if (p)
               *p = '\0';
            len1 = (DBX_ERROR_SIZE - (len2 + 10));
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
         if (lpMsgBuf)
            LocalFree(lpMsgBuf);
#else
         p = (char *) dlerror();
         sprintf(primerr, "Cannot load %s library: Error Code: %d", p_ydb_so->dbname, errno);
         len2 = strlen(error_message);
         if (p) {
            strncpy(primerr, p, DBX_ERROR_SIZE - 1);
            primerr[DBX_ERROR_SIZE - 1] = '\0';
            len1 = (DBX_ERROR_SIZE - (len2 + 10));
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

   if (!p_ydb_so->p_library) {
      goto ydb_load_library_exit;
   }

   sprintf(fun, "%s_init", p_ydb_so->funprfx);
   p_ydb_so->p_ydb_init = (int (*) (void)) mg_dso_sym(p_ydb_so->p_library, (char *) fun);
   if (!p_ydb_so->p_ydb_init) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_ydb_so->dbname, p_ydb_so->libnam, fun);
      goto ydb_load_library_exit;
   }
   sprintf(fun, "%s_exit", p_ydb_so->funprfx);
   p_ydb_so->p_ydb_exit = (int (*) (void)) mg_dso_sym(p_ydb_so->p_library, (char *) fun);
   if (!p_ydb_so->p_ydb_exit) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_ydb_so->dbname, p_ydb_so->libnam, fun);
      goto ydb_load_library_exit;
   }
   sprintf(fun, "%s_malloc", p_ydb_so->funprfx);
   p_ydb_so->p_ydb_malloc = (int (*) (size_t)) mg_dso_sym(p_ydb_so->p_library, (char *) fun);
   if (!p_ydb_so->p_ydb_malloc) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_ydb_so->dbname, p_ydb_so->libnam, fun);
      goto ydb_load_library_exit;
   }
   sprintf(fun, "%s_free", p_ydb_so->funprfx);
   p_ydb_so->p_ydb_free = (int (*) (void *)) mg_dso_sym(p_ydb_so->p_library, (char *) fun);
   if (!p_ydb_so->p_ydb_free) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_ydb_so->dbname, p_ydb_so->libnam, fun);
      goto ydb_load_library_exit;
   }
   sprintf(fun, "%s_data_s", p_ydb_so->funprfx);
   p_ydb_so->p_ydb_data_s = (int (*) (ydb_buffer_t *, int, ydb_buffer_t *, unsigned int *)) mg_dso_sym(p_ydb_so->p_library, (char *) fun);
   if (!p_ydb_so->p_ydb_data_s) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_ydb_so->dbname, p_ydb_so->libnam, fun);
      goto ydb_load_library_exit;
   }
   sprintf(fun, "%s_delete_s", p_ydb_so->funprfx);
   p_ydb_so->p_ydb_delete_s = (int (*) (ydb_buffer_t *, int, ydb_buffer_t *, int)) mg_dso_sym(p_ydb_so->p_library, (char *) fun);
   if (!p_ydb_so->p_ydb_delete_s) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_ydb_so->dbname, p_ydb_so->libnam, fun);
      goto ydb_load_library_exit;
   }
   sprintf(fun, "%s_set_s", p_ydb_so->funprfx);
   p_ydb_so->p_ydb_set_s = (int (*) (ydb_buffer_t *, int, ydb_buffer_t *, ydb_buffer_t *)) mg_dso_sym(p_ydb_so->p_library, (char *) fun);
   if (!p_ydb_so->p_ydb_set_s) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_ydb_so->dbname, p_ydb_so->libnam, fun);
      goto ydb_load_library_exit;
   }
   sprintf(fun, "%s_get_s", p_ydb_so->funprfx);
   p_ydb_so->p_ydb_get_s = (int (*) (ydb_buffer_t *, int, ydb_buffer_t *, ydb_buffer_t *)) mg_dso_sym(p_ydb_so->p_library, (char *) fun);
   if (!p_ydb_so->p_ydb_get_s) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_ydb_so->dbname, p_ydb_so->libnam, fun);
      goto ydb_load_library_exit;
   }
   sprintf(fun, "%s_subscript_next_s", p_ydb_so->funprfx);
   p_ydb_so->p_ydb_subscript_next_s = (int (*) (ydb_buffer_t *, int, ydb_buffer_t *, ydb_buffer_t *)) mg_dso_sym(p_ydb_so->p_library, (char *) fun);
   if (!p_ydb_so->p_ydb_subscript_next_s) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_ydb_so->dbname, p_ydb_so->libnam, fun);
      goto ydb_load_library_exit;
   }
   sprintf(fun, "%s_subscript_previous_s", p_ydb_so->funprfx);
   p_ydb_so->p_ydb_subscript_previous_s = (int (*) (ydb_buffer_t *, int, ydb_buffer_t *, ydb_buffer_t *)) mg_dso_sym(p_ydb_so->p_library, (char *) fun);
   if (!p_ydb_so->p_ydb_subscript_previous_s) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_ydb_so->dbname, p_ydb_so->libnam, fun);
      goto ydb_load_library_exit;
   }
   sprintf(fun, "%s_node_next_s", p_ydb_so->funprfx);
   p_ydb_so->p_ydb_node_next_s = (int (*) (ydb_buffer_t *, int, ydb_buffer_t *, int *, ydb_buffer_t *)) mg_dso_sym(p_ydb_so->p_library, (char *) fun);
   if (!p_ydb_so->p_ydb_node_next_s) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_ydb_so->dbname, p_ydb_so->libnam, fun);
      goto ydb_load_library_exit;
   }
   sprintf(fun, "%s_node_previous_s", p_ydb_so->funprfx);
   p_ydb_so->p_ydb_node_previous_s = (int (*) (ydb_buffer_t *, int, ydb_buffer_t *, int *, ydb_buffer_t *)) mg_dso_sym(p_ydb_so->p_library, (char *) fun);
   if (!p_ydb_so->p_ydb_node_previous_s) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_ydb_so->dbname, p_ydb_so->libnam, fun);
      goto ydb_load_library_exit;
   }
   sprintf(fun, "%s_incr_s", p_ydb_so->funprfx);
   p_ydb_so->p_ydb_incr_s = (int (*) (ydb_buffer_t *, int, ydb_buffer_t *, ydb_buffer_t *, ydb_buffer_t *)) mg_dso_sym(p_ydb_so->p_library, (char *) fun);
   if (!p_ydb_so->p_ydb_incr_s) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_ydb_so->dbname, p_ydb_so->libnam, fun);
      goto ydb_load_library_exit;
   }
   sprintf(fun, "%s_ci", p_ydb_so->funprfx);
   p_ydb_so->p_ydb_ci = (int (*) (const char *, ...)) mg_dso_sym(p_ydb_so->p_library, (char *) fun);
   if (!p_ydb_so->p_ydb_ci) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_ydb_so->dbname, p_ydb_so->libnam, fun);
      goto ydb_load_library_exit;
   }
   sprintf(fun, "%s_cip", p_ydb_so->funprfx);
   p_ydb_so->p_ydb_cip = (int (*) (ci_name_descriptor *, ...)) mg_dso_sym(p_ydb_so->p_library, (char *) fun);
   if (!p_ydb_so->p_ydb_cip) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_ydb_so->dbname, p_ydb_so->libnam, fun);
      goto ydb_load_library_exit;
   }

   sprintf(fun, "%s_lock_incr_s", p_ydb_so->funprfx);
   p_ydb_so->p_ydb_lock_incr_s = (int (*) (unsigned long long, ydb_buffer_t *, int, ydb_buffer_t *)) mg_dso_sym(p_ydb_so->p_library, (char *) fun);
   if (!p_ydb_so->p_ydb_lock_incr_s) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_ydb_so->dbname, p_ydb_so->libnam, fun);
      goto ydb_load_library_exit;
   }

   sprintf(fun, "%s_lock_decr_s", p_ydb_so->funprfx);
   p_ydb_so->p_ydb_lock_decr_s = (int (*) (ydb_buffer_t *, int, ydb_buffer_t *)) mg_dso_sym(p_ydb_so->p_library, (char *) fun);
   if (!p_ydb_so->p_ydb_lock_decr_s) {
      sprintf(error_message, "Error loading %s library: %s; Cannot locate the following function : %s", p_ydb_so->dbname, p_ydb_so->libnam, fun);
      goto ydb_load_library_exit;
   }

   sprintf(fun, "%s_zstatus", p_ydb_so->funprfx);
   p_ydb_so->p_ydb_zstatus = (void (*) (ydb_char_t *, ydb_long_t)) mg_dso_sym(p_ydb_so->p_library, (char *) fun);

   sprintf(fun, "%s_tp_s", p_ydb_so->funprfx);
   p_ydb_so->p_ydb_tp_s = (int (*) (ydb_tpfnptr_t, void *, const char *, int, ydb_buffer_t *)) mg_dso_sym(p_ydb_so->p_library, (char *) fun);

   p_ydb_so->loaded = 1;

ydb_load_library_exit:

   if (error_message[0]) {
      p_ydb_so->loaded = 0;
      error_code = 1009;
      result = YDB_FAILURE;
      return result;
   }

   return YDB_OK;
}


int mg_set_size(unsigned char *str, unsigned long data_len)
{
   str[0] = (unsigned char) (data_len >> 0);
   str[1] = (unsigned char) (data_len >> 8);
   str[2] = (unsigned char) (data_len >> 16);
   str[3] = (unsigned char) (data_len >> 24);

   return 0;
}


unsigned long mg_get_size(unsigned char *str)
{
   unsigned long size;

   size = ((unsigned char) str[0]) | (((unsigned char) str[1]) << 8) | (((unsigned char) str[2]) << 16) | (((unsigned char) str[3]) << 24);
   return size;
}


void * mg_realloc(void *p, int curr_size, int new_size, short id)
{
   if (dbx_ext_realloc) {
      p = (void *) dbx_ext_realloc((void *) p, (unsigned long) new_size);
   }
   else {
      if (new_size >= curr_size) {
         if (p) {
            mg_free((void *) p, 0);
         }

#if defined(_WIN32)
         p = (void *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, new_size + 32);
#else
         p = (void *) mg_malloc(new_size, id);
#endif
      }
   }

   /* printf("\r\n curr_size=%d; new_size=%d;\r\n", curr_size, new_size); */

   return p;
}


void * mg_malloc(int size, short id)
{
   void *p;

   if (dbx_ext_malloc) {
      p = (void *) dbx_ext_malloc((unsigned long) size);
   }
   else {
#if defined(_WIN32)
      p = (void *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 32);
#else
      p = (void *) malloc(size);
#endif
   }

   /* printf("\nmg_malloc: size=%d; id=%d; p=%p;", size, id, p); */

   return p;
}


int mg_free(void *p, short id)
{
   /* printf("\nmg_free: id=%d; p=%p;", id, p); */

   if (dbx_ext_free) {
      dbx_ext_free((void *) p);
   }
   else {
#if defined(_WIN32)
      HeapFree(GetProcessHeap(), 0, p);
#else
      free((void *) p);
#endif
   }

   return 0;
}


int mg_lcase(char *string)
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


int mg_log_init(DBXLOG *p_log)
{
   p_log->log_errors = 0;
   p_log->log_file[0] = '\0';
   p_log->log_level[0] = '\0';

   return 0;
}


int mg_log_event(DBXLOG *p_log, char *message, char *title, int level)
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

   sprintf(heading, ">>> Time: %s; Build: %s pid=%lu;tid=%lu;", timestr, DBX_VERSION, (unsigned long) mg_current_process_id(), (unsigned long) mg_current_thread_id());

   len = (int) strlen(heading) + (int) strlen(title) + (int) strlen(message) + 20;

   if (len < 2000)
      p_buffer = buffer;
   else
      p_buffer = (char *) malloc(sizeof(char) * len);

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


int mg_log_buffer(DBXLOG *p_log, char *buffer, int buffer_len, char *title, int level)
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
   p = (char *) malloc(sizeof(char) * size);
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

   mg_log_event(p_log, (char *) p, title, level);

   free((void *) p);

   return 1;
}


DBXPLIB mg_dso_load(char * library)
{
   DBXPLIB p_library;

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


DBXPROC mg_dso_sym(DBXPLIB p_library, char * symbol)
{
   DBXPROC p_proc;

#if defined(_WIN32)
   p_proc = GetProcAddress(p_library, symbol);
#else
   p_proc  = (void *) dlsym(p_library, symbol);
#endif

   return p_proc;
}



int mg_dso_unload(DBXPLIB p_library)
{

#if defined(_WIN32)
   FreeLibrary(p_library);
#else
   dlclose(p_library); 
#endif

   return 1;
}


DBXTHID mg_current_thread_id(void)
{
#if defined(_WIN32)
   return (DBXTHID) GetCurrentThreadId();
#else
   return (DBXTHID) pthread_self();
#endif
}


unsigned long mg_current_process_id(void)
{
#if defined(_WIN32)
   return (unsigned long) GetCurrentProcessId();
#else
   return ((unsigned long) getpid());
#endif
}


int mg_mutex_create(DBXMUTEX *p_mutex)
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



int mg_mutex_lock(DBXMUTEX *p_mutex, int timeout)
{
   int result;
   DBXTHID tid;
#ifdef _WIN32
   DWORD result_wait;
#endif

   result = 0;

   if (!p_mutex->created) {
      return -1;
   }

   tid = mg_current_thread_id();
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
      printf("\r\nmg_mutex_lock: Returned WAIT_ABANDONED state");
      result = -1;
   }
   else if (result_wait == WAIT_TIMEOUT) {
      printf("\r\nmg_mutex_lock: Returned WAIT_TIMEOUT state");
      result = -1;
   }
   else if (result_wait == WAIT_FAILED) {
      printf("\r\nmg_mutex_lock: Returned WAIT_FAILED state: Error Code: %d", GetLastError());
      result = -1;
   }
   else {
      printf("\r\nmg_mutex_lock: Returned Unrecognized state: %d", result_wait);
      result = -1;
   }
#else
   result = pthread_mutex_lock(&(p_mutex->h_mutex));
#endif

   p_mutex->thid = tid;
   p_mutex->stack = 0;

   return result;
}


int mg_mutex_unlock(DBXMUTEX *p_mutex)
{
   int result;
   DBXTHID tid;

   result = 0;

   if (!p_mutex->created) {
      return -1;
   }

   tid = mg_current_thread_id();
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


int mg_mutex_destroy(DBXMUTEX *p_mutex)
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


int mg_init_critical_section(void *p_crit)
{
#if defined(_WIN32)
   InitializeCriticalSection((LPCRITICAL_SECTION) p_crit);
#endif

   return 0;
}


int mg_delete_critical_section(void *p_crit)
{
#if defined(_WIN32)
   DeleteCriticalSection((LPCRITICAL_SECTION) p_crit);
#endif

   return 0;
}


int mg_enter_critical_section(void *p_crit)
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


int mg_leave_critical_section(void *p_crit)
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


int mg_sleep(unsigned long msecs)
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


char mg_b64_ntc(unsigned char n)
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


unsigned char mg_b64_ctn(char c)
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


int mg_b64_encode(char *from, int length, char *to, int quads)
{
   int i = 0;
   char *tot = to;
   int qc = 0;
   unsigned char c;
   unsigned char d;

   while (i < length) {
      c = from[i];
      *to++ = (char) mg_b64_ntc((unsigned char) (c / 4));
      c = c * 64;
     
      i++;

      if (i >= length) {
         *to++ = mg_b64_ntc((unsigned char) (c / 4));
         *to++ = '=';
         *to++ = '=';
         break;
      }
      d = from[i];
      *to++ = mg_b64_ntc((unsigned char) (c / 4 + d / 16));
      d = d * 16;

      i++;


      if (i >= length) {
         *to++ = mg_b64_ntc((unsigned char) (d / 4));
         *to++ = '=';
         break;
      }
      c = from[i];
      *to++ = mg_b64_ntc((unsigned char) (d / 4 + c / 64));
      c=c * 4;

      i++;

      *to++ = mg_b64_ntc((unsigned char) (c / 4));

      qc ++;
      if (qc == quads) {
         *to++ = '\n';
         qc = 0;
      }
   }

   return ((int) (to - tot));
}


int mg_b64_decode(char *from, int length, char *to)
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
         c = mg_b64_ctn(from[i++]);
      while ((d == 100) && (i < length))
         d = mg_b64_ctn(from[i++]);
      while ((e == 100) && (i < length))
         e = mg_b64_ctn(from[i++]);
      while ((f == 100) && (i < length))
         f = mg_b64_ctn(from[i++]);

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


int mg_b64_enc_buffer_size(int l, int q)
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


int mg_b64_strip_enc_buffer(char *buf, int length)
{
   int i;
   int ret = 0;

   for (i = 0;i < length;i ++)
      if (mg_b64_ctn(buf[i]) != 100)
         buf[ret++] = buf[i];
 
   return ret;
}


int mg_hex_encode(char *from, int length, char *to)
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


unsigned long mg_crc32_checksum(char *buffer, size_t len)
{
   register unsigned long oldcrc32;

   oldcrc32 = 0xFFFFFFFF;

   for ( ; len; --len, ++ buffer) {
      oldcrc32 = UPDC32(*buffer, oldcrc32);
   }

   return ~oldcrc32;
}

#if !defined(_WIN32)
void * mg_stdin_listener(void *pargs)
{
   int rc, clilen;
   int fd;
   int pipefd[2];
   char buffer[256], error[512];

   fd = dup(STDIN_FILENO);
   pipe(pipefd);
   dup2(pipefd[0], STDIN_FILENO);
   close(pipefd[0]);

   pthread_mutex_lock(&dbx_cond_mutex);
   dbx_cond_flag = 1;
   pthread_cond_broadcast(&dbx_cond);
   pthread_mutex_unlock(&dbx_cond_mutex);

   while (1) {
      rc = mg_tcpsrv_recv(buffer, 255, 0, 0, error);
      if (rc < 0 && errno == EINTR) {
         continue;
      }
      if (rc < 1) {
         break;
      }
      buffer[rc] = '\0';
      rc = write(pipefd[1], buffer, rc);

      /* fflush(stdin); - not standard */
      /* mg_log_buffer(p_log, buffer, rc, "mg_stdin_listener", 0); */
   }

   dup2(fd, STDIN_FILENO);

   /* mg_log_event(p_log, "exit", "mg_stdin_listener", 0); */

   return NULL;
}


void * mg_stdout_listener(void *pargs)
{
   int rc, clilen;
   int fd;
   int pipefd[2];
   char buffer[256], error[512];

   fd = dup(STDOUT_FILENO);
   pipe(pipefd);
   dup2(pipefd[1], STDOUT_FILENO);
   close(pipefd[1]);

   pthread_mutex_lock(&dbx_cond_mutex);
   dbx_cond_flag = 1;
   pthread_cond_broadcast(&dbx_cond);
   pthread_mutex_unlock(&dbx_cond_mutex);

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
      mg_tcpsrv_send(buffer, rc, 1, error);
      /* mg_log_buffer(p_log, buffer, rc, "mg_stdout_listener", 0); */
   }

   dup2(fd, STDOUT_FILENO);

   /* mg_log_event(p_log, "exit", "mg_stdout_listener", 0); */

   return NULL;
}


void * mg_domsrv_listener(void *pargs)
{
   int rc, clilen;

   unlink(p_tcpsrv->domsrv_name);

   p_tcpsrv->domsrv_sockfd = mg_domsrv_init();

   if (p_tcpsrv->domsrv_sockfd < 0) {
      sprintf(error_message, "ERROR opening socket (%d)", errno);
      mg_log_event(p_log, error_message, "mg_domsrv_init: error", 0);
      return NULL;
   }

   listen(p_tcpsrv->domsrv_sockfd, 5);

   clilen = sizeof(p_tcpsrv->domcli_addr);

   while (1) {
      p_tcpsrv->domcli_sockfd = accept(p_tcpsrv->domsrv_sockfd, (struct sockaddr *) &(p_tcpsrv->domcli_addr), &clilen);

      if (p_tcpsrv->domcli_sockfd < 0) {
         sprintf(error_message, "ERROR on accept (%d)", errno);
         mg_log_event(p_log, error_message, "mg_domsrv_init: error", 0);
         break;
      }
      rc = mg_domsrv_sendfd(0);
   }

   /* mg_log_event(p_log, "exit", "mg_domsrv_init", 0); */

   return NULL;
}


int mg_domsrv_init()
{
   int rc;

   unlink(p_tcpsrv->domsrv_name);

   p_tcpsrv->domsrv_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);

   if (p_tcpsrv->domsrv_sockfd < 0) {
      sprintf(error_message, "ERROR opening socket (%d)", errno);
      mg_log_event(p_log, error_message, "mg_domsrv_init: error", 0);
      return -1;
   }

   bzero((char *) &(p_tcpsrv->domsrv_addr), sizeof(p_tcpsrv->domsrv_addr));

   p_tcpsrv->domsrv_addr.sun_family = AF_UNIX;
   strcpy(p_tcpsrv->domsrv_addr.sun_path, p_tcpsrv->domsrv_name);

   if (bind(p_tcpsrv->domsrv_sockfd, (struct sockaddr *) &(p_tcpsrv->domsrv_addr), sizeof(p_tcpsrv->domsrv_addr)) < 0) {
      sprintf(error_message, "ERROR on binding for domain socket %s (%d)", p_tcpsrv->domsrv_name, errno);
      mg_log_event(p_log, error_message, "mg_domsrv_init: error", 0);
      close(p_tcpsrv->domsrv_sockfd);
      p_tcpsrv->domsrv_sockfd = -1;
      return -1;
   }

   return p_tcpsrv->domsrv_sockfd;
}


int mg_domsrv_sendfd(int sockfd)
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
   count = mg_get_size(buffer);

/*
{
   char buffer[256];
   sprintf(buffer, "send this socket index rc=%d; count=%d; errno=%d", rc, count, errno);
   mg_log_event(p_log, buffer, "mg_domsrv_sendfd", 0);
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
   mg_log_event(p_log, buffer, "mg_domsrv_sendfd result", 0);
}
*/
   close(sockfd);

   return rc;
}


int mg_domsrv_recvfd(char *key, char *options, char *error)
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
   dbx_cond_flag = 0;
   pthread_attr_init(&attr);
   pthread_attr_getstacksize(&attr, &stacksize);
   newstacksize = 0x40000; /* 262144 */
   pthread_attr_setstacksize(&attr, newstacksize);

   rc = pthread_create(&(p_tcpsrv->stdout_tid), &attr, mg_stdout_listener, (void *) NULL);
   if (rc) {
      sprintf(error, "ERROR creating thread for mg_stdout_listener (%d)", errno);
      mg_log_event(p_log, error, "mg_tcpsrv_init: error", 0);
      return YDB_FAILURE;
   }
   pthread_mutex_lock(&dbx_cond_mutex);
   while (!dbx_cond_flag) {
      pthread_cond_wait(&dbx_cond, &dbx_cond_mutex);
   }
   pthread_mutex_unlock(&dbx_cond_mutex);

   if (mapstdin) {
      dbx_cond_flag = 0;
      pthread_attr_init(&attr);
      pthread_attr_getstacksize(&attr, &stacksize);
      newstacksize = 0x40000; /* 262144 */
      pthread_attr_setstacksize(&attr, newstacksize);
      rc = pthread_create(&(p_tcpsrv->stdout_tid), &attr, mg_stdin_listener, (void *) NULL);
      if (rc) {
         sprintf(error, "ERROR creating thread for mg_stdin_listener (%d)", errno);
         mg_log_event(p_log, error, "mg_tcpsrv_init: error", 0);
         return YDB_FAILURE;
      }
      pthread_mutex_lock(&dbx_cond_mutex);
      while (!dbx_cond_flag) {
         pthread_cond_wait(&dbx_cond, &dbx_cond_mutex);
      }
      pthread_mutex_unlock(&dbx_cond_mutex);
   }

   p_tcpsrv->wbuffer_size = (WORK_BUFFER - 1);
   p_tcpsrv->wbuffer_datasize = 0;
   p_tcpsrv->wbuffer_offset = 0;

   p_tcpsrv->count = (int) strtol(key, NULL, 10);
   p = strstr(key, "|");
   if (!p) {
      strcpy(error, "mg_domsrv_recvfd: bad key");
      return YDB_FAILURE;
   }
   p ++;
   p_tcpsrv->port = (int) strtol(p, NULL, 10);
   p = strstr(key, "|||");
   if (!p) {
      strcpy(error, "mg_domsrv_recvfd: bad key");
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
      sprintf(error, "mg_domsrv_recvfd: bad domain socket (%d)", errno);
      mg_log_event(p_log, error, "mg_domsrv_recvfd: error", 0);
      return YDB_FAILURE;
   }

   memset(&addr, 0, sizeof(struct sockaddr_un));
   addr.sun_family = AF_UNIX;
   strcpy(addr.sun_path, p_tcpsrv->domsrv_name);

   if (connect(sfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_un)) == -1) {
      sprintf(error, "mg_domsrv_recvfd: cannot connect to domain socket (%d)", errno);
      mg_log_event(p_log, error, "mg_domsrv_recvfd: error", 0);
      return YDB_FAILURE;
   }

   mg_set_size((unsigned char *) buffer, (unsigned long)  p_tcpsrv->count);
   rc = send(sfd, buffer, 4, 0);
   if (rc < 0) {
      sprintf(error, "mg_domsrv_recvfd: cannot send index (%d)", errno);
      mg_log_event(p_log, error, "mg_domsrv_recvfd: error", 0);
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
      sprintf(error, "mg_domsrv_recvfd: cannot read from domain socket (%d)", errno);
      mg_log_event(p_log, error, "mg_domsrv_recvfd: error", 0);
      return YDB_FAILURE;
   }

   cm = CMSG_FIRSTHDR(&msg);
   if (cm->cmsg_type != SCM_RIGHTS) {
      sprintf(error, "mg_domsrv_recvfd: unknown mesasge type from domain socket (%d)", errno);
      mg_log_event(p_log, error, "mg_domsrv_recvfd: error", 0);
      return YDB_FAILURE;
   }

   p_tcpsrv->cli_sockfd = *(int *) CMSG_DATA(cm);

   rc = setsockopt(p_tcpsrv->cli_sockfd, IPPROTO_TCP, TCP_NODELAY, (const char *) &flag, sizeof(int));

   close(sfd);

/*
{
   char buffer[256];
   sprintf(buffer, "send this socket sockfd=%d rc=%d; errno=%d", p_tcpsrv->cli_sockfd, rc, errno);
   mg_log_event(p_log, buffer, "mg_domsrv_recvfd result: should have socket now 1", 0);
}
*/

/* experiental code */
#if 0
   if (1) {
      strcpy(p_ydb_so->libdir, "/usr/local/lib/yottadb/r130");
      ydb_load_library(p_ydb_so);
   
      if (p_ydb_so->p_library) {
         rc = p_ydb_so->p_ydb_init();
      }
   }
#endif

   return YDB_OK;
}


int mg_tcpsrv_init(int port, char *options, char *error)
{
   int rc, n, sockfd, newsockfd, portno, clilen;
   const int on = 1;
   char buffer[256];
   pthread_attr_t attr;
   size_t stacksize, newstacksize;
/*
   mg_log_event(p_log, "initialise", "mg_tcpsrv_init", 0);
*/
   for (n = 0; n < DBX_MAX_CLIFD; n ++) {
      p_tcpsrv->new_sockfd[n] = 0;
   }

   p_tcpsrv->count = 0;
   p_tcpsrv->port = port;
   p_tcpsrv->srv_sockfd = socket(AF_INET, SOCK_STREAM, 0);

   if (p_tcpsrv->srv_sockfd < 0) {
      sprintf(error, "ERROR opening socket (%d)", errno);
      mg_log_event(p_log, error, "mg_tcpsrv_init: error", 0);
      return YDB_FAILURE;
   }

   setsockopt(p_tcpsrv->srv_sockfd, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on));

   bzero((char *) &(p_tcpsrv->srv_addr), sizeof(p_tcpsrv->srv_addr));

   p_tcpsrv->srv_addr.sin_family = AF_INET;
   p_tcpsrv->srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
   p_tcpsrv->srv_addr.sin_port = htons(port);

   if (bind(p_tcpsrv->srv_sockfd, (struct sockaddr *) &(p_tcpsrv->srv_addr), sizeof(p_tcpsrv->srv_addr)) < 0) {
      sprintf(error, "ERROR on binding (%d)", errno);
      mg_log_event(p_log, error, "mg_tcpsrv_init: error", 0);
      return YDB_FAILURE;
   }
   if (listen(p_tcpsrv->srv_sockfd, 5) < 0) {
      sprintf(error, "ERROR on listen (%d)", errno);
      mg_log_event(p_log, error, "mg_tcpsrv_init: error", 0);
      return YDB_FAILURE;
   }

   sprintf(p_tcpsrv->domsrv_name, "/tmp/mg_pwind%ld.str", (unsigned long) getpid());
/*
{
   char buffer[256];
   sprintf(buffer, "sfd: srv_sockfd=%d; errno=%d", p_tcpsrv->srv_sockfd, errno);
   mg_log_event(p_log, p_tcpsrv->domsrv_name, "mg_tcpsrv_init", 0);
}
*/
   pthread_attr_init(&attr);
   pthread_attr_getstacksize(&attr, &stacksize);
   newstacksize = 0x40000; /* 262144 */
   pthread_attr_setstacksize(&attr, newstacksize);
   rc = pthread_create(&(p_tcpsrv->domsrv_tid), &attr, mg_domsrv_listener, (void *) NULL);
   if (rc) {
      sprintf(error, "ERROR creating thread for mg_domsrv_listener (%d)", errno);
      mg_log_event(p_log, error, "mg_tcpsrv_init: error", 0);
      return YDB_FAILURE;
   }

   return YDB_OK;
}


int mg_tcpsrv_accept(char *key, char *error)
{
   int rc, clilen, count, smax, len;
   fd_set socket_set;
   struct timeval timeout;

   error[0] = '\0';
   count = -1;
   if (key[0]) {
/*
      mg_log_event(p_log, key, "mg_tcpsrv_accept: existing key", 0);
*/
      count = (int) strtol(key, NULL, 10);
      if (count >= DBX_MAX_CLIFD) {
         count = -1;
      }
   }
   if (count == -1) {
      count = p_tcpsrv->count;
      p_tcpsrv->count ++;
      if (p_tcpsrv->count >= DBX_MAX_CLIFD) {
         p_tcpsrv->count = 0;
      }
      sprintf(key, "%d|%d|||%s|", count, p_tcpsrv->port, p_tcpsrv->domsrv_name);
/*
      mg_log_event(p_log, key, "mg_tcpsrv_accept: new key", 0);
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
   mg_log_event(p_log, buffer, "mg_tcpsrv_accept: select", 0);
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
   mg_log_event(p_log, buffer, "mg_tcpsrv_accept", 0);
}
*/

   return rc;
}


int mg_tcpsrv_send(char *data, int len, int flush, char *error)
{
   int rc;

   rc = send(p_tcpsrv->cli_sockfd, data, len, 0);

   if (rc == 0) {
      strcpy(error, "<EOF>");
   }
   else if (rc < 0) {
      sprintf(error, "mg_tcpsrv_send (%d)", errno);
   }
/*
{
   char buffer[256];
   sprintf(buffer, "rc=%d; p_tcpsrv->cli_sockfd=%d; errno=%d", rc, p_tcpsrv->cli_sockfd, errno);
   mg_log_event(p_log, buffer, "mg_tcpsrv_send", 0);
}
*/
   return rc;
}


int mg_tcpsrv_recv(char *data, int dsize, int len, int timeout, char *error)
{
   int rc, eno, timed_out;
   unsigned int avail, got, get;
   fd_set rset, eset;
   struct timeval tval;

/*
{
   char buffer[256];
   sprintf(buffer, "START: dsize=%d; len=%d; timeout=%d; wbuffer_datasize=%d; wbuffer_offset=%d", dsize, len, timeout, p_tcpsrv->wbuffer_datasize, p_tcpsrv->wbuffer_offset);
   mg_log_event(p_log, buffer, "mg_tcpsrv_recv", 0);
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
   mg_log_event(p_log, buffer, "mg_tcpsrv_recv", 0);
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
   mg_log_event(p_log, buffer, "mg_tcpsrv_recv", 0);
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
   mg_log_buffer(p_log, p_tcpsrv->wbuffer, rc, buffer, 0);
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
      sprintf(error, "mg_tcpsrv_recv (%d)", errno);
   }
/*
{
   char buffer[512];
   sprintf(buffer, "rc=%d; p_tcpsrv->cli_sockfd=%d; errno=%d", rc, p_tcpsrv->cli_sockfd, errno);
   mg_log_event(p_log, buffer, "mg_tcpsrv_recv a", 0);
   mg_log_event(p_log, data, "mg_tcpsrv_recv b", 0);
}
*/
   return rc;
}


int mg_tcpsrv_recv_message(char *data, int dsize, int *len, int *cmnd, int timeout, char *error)
{
   int rc;

   rc = mg_tcpsrv_recv(data, dsize, 5, timeout, error);
   if (rc != 5) {
      rc = YDB_FAILURE;
      return rc;
   }

   *len = (int) mg_get_size((unsigned char *) data) - 5;
   *cmnd = (int) data[4];

   if (*len > 0) {
      rc = mg_tcpsrv_recv(data, dsize, *len, timeout, error);
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
         lenx = (int) mg_get_size((unsigned char *) p);
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
            mg_log_buffer(p_log, data, *len, buffer, 0);
         }
*/
      }

      datax.buf_addr = (char *) (p_tcpsrv->wbuffer + 5);
      datax.len_alloc = (unsigned int) (p_tcpsrv->wbuffer_size - 5);
      datax.len_used = 0;

      rc = p_ydb_so->p_ydb_get_s(&global, n - 1, &key[0], &datax);

      mg_set_size((unsigned char *) p_tcpsrv->wbuffer, (unsigned long) datax.len_used);
      sort = 1;
      type = 1;
      p_tcpsrv->wbuffer[4] = (unsigned char) ((sort * 20) + type);
/*
      {
         char buffer[256];
         sprintf(buffer, "result: p_ydb_get_s=%d; len=%d; cmnd=%d", rc, datax.len_used, *cmnd);
         mg_log_buffer(p_log, p_tcpsrv->wbuffer, datax.len_used + 5, buffer, 0);
      }
*/
      mg_tcpsrv_send(p_tcpsrv->wbuffer, datax.len_used + 5, 1, error);
      *cmnd = 0;
   }

#endif

   return rc;
}


int mg_tcpsrv_close(char *key)
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

