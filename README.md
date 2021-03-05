# mg\_pwind

Access to OS libraries (e.g. the cryptography library) from **YottaDB** code.

Chris Munt <cmunt@mgateway.com>  
5 March 2021, M/Gateway Developments Ltd [http://www.mgateway.com](http://www.mgateway.com)

* Current Release: Version: 1.0; Revision 1.
* [Release Notes](#RelNotes) can be found at the end of this document.

Contents

* [Overview](#Overview")
* [Pre-requisites](#PreReq")
* [Installing mg\_pwind](#Install)
* [Invocation of mg\_pwind functions](#DBFunctions)
* [For the future](#Future)
* [License](#License)


## <a name="Overview"></a> Overview 

The **YottaDB** *Process Window* (**mg\_pwind**) library is an Open Source solution to provide easy access to functionality contained in external shared libraries.

The **mg\_pwind** library provides access to the cryptographic functions commonly used in web application development. To provide this functionality, **mg_pwind** makes use of the **OpenSSL** cryptography library: **libcrypto.so**.

## <a name="PreReq"></a> Pre-requisites

The OpenSSL libraries:

       https://www.openssl.org/

These libraries are pre-installed on most Linux systems.  In order to build **mg_pwind.so** the **OpenSSL** development files will need to be installed.  For example:

       apt-get install libssl-dev

## <a name="Install"></a> Installing mg\_pwind

Working in the **/src** directory of the distribution, edit the following two files to reflect the layout of your **YottaDB** installation.  The instructions given here assume a standard 'out of the box' installation of **YottaDB** (version 1.30) deployed in the following location:

       /usr/local/lib/yottadb/r130

Assuming that you will install **mg\_pwind** in this directory, first edit the following line in **Makefile** to reflect this installation location:

       MGYDBDIR=/usr/local/lib/yottadb/r130

Now edit the top line of the **YottaDB** interface file **mg\_pwind.xc** to give the full name and path to the **mg\_pwind.so** library:

       /usr/local/lib/yottadb/r130/mg_pwind.so
 
Finally, build and install the **mg\_pwind** library:

       make
       make install

You should now see the **mg\_pwind** library and its associated interface file installed in the **YottaDB** directory:

       /usr/local/lib/yottadb/r130/mg_pwind.so
       /usr/local/lib/yottadb/r130/mg_pwind.xc


## <a name="DBFunctions"> Invocation of mg\_pwind functions

Before invoking **mg\pwind** functions the following environment variable (**ydb\_xc\_pwind**) must be set before starting **YottaDB** processes:

       export ydb_xc_pwind=/usr/local/lib/yottadb/r130/mg_pwind.xc

Of course, modify the path to suit your own installation.

Many of the functions described here will return an **error** variable.  Success of the operation is indicated by this variable being returned as an empty string ("").

Some functions include a **mode** flag.  Set this flag as follows:

* mode=0: The default.  Return the raw hash or HMAC value.
* mode=1: Return the hash or HMAC value as B64 encoded.
* mode=2: Return the hash or HMAC value as a string of HEX values.

When calling **mg\_pwind** functions be sure to pass output variables by reference (i.e. preceded by a period character).

### Get the version of the mg\_pwind library

       do &pwind.version(.<version>)
      
Example:

       do &pwind.version(.vers)
       write !,"version: ",vers


### Specifying the location of the OpenSSL libraries

It will not be necessary to use this function for most systems as the **libcrypto.so** library is usually readily available from the OS known directories for shared libraries.  However, if you need to specify an alternative location for the **libcrypto.so** library then use this function to specify the name and full path. 

       do &pwind.cryptlibrary(<cryptlibrary>)
      
Example:

      do &pwind.cryptlibrary("/unusual/location/libcrypto.so")

### Get the version of the OpenSSL libraries

       do &pwind.sslversion(.<version>, .<error>)
      
Example:

      do &pwind.sslversion(.vers,.error)
      if error'="" w !,"error: ",error
      write !,"sslversion: ",vers

### Generate SHA1 hash

       do &pwind.sha1(<data>, <mode>, .<hash>, .<error>)
      
Example:

      do &pwind.sha1("my data",2,.hash,.error)
      if error'="" w !,"error: ",error
      write !,"SHA1 hash: ",hash


### Generate SHA256 hash

       do &pwind.sha256(<data>, <mode>, .<hash>, .<error>)
      
Example:

      do &pwind.sha256("my data",2,.hash,.error)
      if error'="" w !,"error: ",error
      write !,"SHA256 hash: ",hash

### Generate SHA512 hash

       do &pwind.sha512(<data>, <mode>, .<hash>, .<error>)
      
Example:

      do &pwind.sha512("my data",2,.hash,.error)
      if error'="" w !,"error: ",error
      write !,"SHA512 hash: ",hash

### Generate MD5 hash

       do &pwind.md5(<data>, <mode>, .<hash>, .<error>)
      
Example:

      do &pwind.md5("my data",2,.hash,.error)
      if error'="" w !,"error: ",error
      write !,"MD5 hash: ",hash

### Generate SHA1 HMAC

       do &pwind.hmacsha1(<key>, <data>, <mode>, .<hmac>, .<error>)
      
Example:

      do &pwind.hmacsha1("my key","my data",2,.hmac,.error)
      if error'="" w !,"error: ",error
      write !,"SHA1 HMAC: ",hmac

### Generate SHA256 HMAC

       do &pwind.hmacsha256(<key>, <data>, <mode>, .<hmac>, .<error>)
      
Example:

      do &pwind.hmacsha256("my key","my data",2,.hmac,.error)
      if error'="" w !,"error: ",error
      write !,"SHA256 HMAC: ",hmac

### Generate SHA512 HMAC

       do &pwind.hmacsha512(<key>, <data>, <mode>, .<hmac>, .<error>)
      
Example:

      do &pwind.hmacsha512("my key","my data",2,.hmac,.error)
      if error'="" w !,"error: ",error
      write !,"SHA512 HMAC: ",hmac

### Generate MD5 HMAC

       do &pwind.hmacmd5(<key>, <data>, <mode>, .<hmac>, .<error>)
      
Example:

      do &pwind.hmacmd5("my key","my data",2,.hmac,.error)
      if error'="" w !,"error: ",error
      write !,"MD5 HMAC: ",hmac

### B64 encode

       do &pwind.encodeb64(<data>, .<b64>)
      
Example:

      do &pwind.encodeb64("my data",.b64)
      write !,"B64 encode: ",b64

### B64 decode

       do &pwind.decodeb64(<b64>, .<data>)
      
Example:

      do &pwind.decodeb64(b64,.data)
      write !,"B64 decode: ",data

### Generate CRC32 checksum

       do &pwind.crc32(<data>, .<crc32>)
      
Example:

      do &pwind.crc32("my data",.crc32)
      write !,"CRC32: ",crc32


## <a name="Future"></a> For the future

Further functions (and access to other OS libraries) will be added to **mg\_pwind** as required.


## <a name="License"></a> License

Copyright (c) 2018-2021 M/Gateway Developments Ltd,
Surrey UK.                                                      
All rights reserved.
 
http://www.mgateway.com                                                  
Email: cmunt@mgateway.com
 
 
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.      


## <a name="RelNotes"></a>Release Notes

### v1.0.1 (5 March 2021)

* Initial Release
