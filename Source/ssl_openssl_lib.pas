{==============================================================================|
| Project : Ararat Synapse                                       | 003.007.002 |
|==============================================================================|
| Content: SSL support by OpenSSL                                              |
|==============================================================================|
| Copyright (c)1999-2013, Lukas Gebauer                                        |
| All rights reserved.                                                         |
|                                                                              |
| Redistribution and use in source and binary forms, with or without           |
| modification, are permitted provided that the following conditions are met:  |
|                                                                              |
| Redistributions of source code must retain the above copyright notice, this  |
| list of conditions and the following disclaimer.                             |
|                                                                              |
| Redistributions in binary form must reproduce the above copyright notice,    |
| this list of conditions and the following disclaimer in the documentation    |
| and/or other materials provided with the distribution.                       |
|                                                                              |
| Neither the name of Lukas Gebauer nor the names of its contributors may      |
| be used to endorse or promote products derived from this software without    |
| specific prior written permission.                                           |
|                                                                              |
| THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"  |
| AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE    |
| IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE   |
| ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR  |
| ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL       |
| DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR   |
| SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER   |
| CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT           |
| LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY    |
| OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH  |
| DAMAGE.                                                                      |
|==============================================================================|
| The Initial Developer of the Original Code is Lukas Gebauer (Czech Republic).|
| Portions created by Lukas Gebauer are Copyright (c)2002-2013.                |
| Portions created by Petr Fejfar are Copyright (c)2011-2012.                  |
| All Rights Reserved.                                                         |
|==============================================================================|
| Contributor(s):                                                              |
|   Tomas Hajny (OS2 support)                                                  |
|==============================================================================|
| History: see HISTORY.HTM from distribution package                           |
|          (Found at URL: http://www.ararat.cz/synapse/)                       |
|==============================================================================}

{
Special thanks to Gregor Ibic <gregor.ibic@intelicom.si>
 (Intelicom d.o.o., http://www.intelicom.si)
 for good inspiration about begin with SSL programming.
}

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}
{$H+}
{$IFDEF VER125}
  {$DEFINE BCB}
{$ENDIF}
{$IFDEF BCB}
  {$ObjExportAll On}
  (*$HPPEMIT 'namespace ssl_openssl_lib { using System::Shortint; }' *)
{$ENDIF}

//old Delphi does not have MSWINDOWS define.
{$IFDEF WIN32}
  {$IFNDEF MSWINDOWS}
    {$DEFINE MSWINDOWS}
  {$ENDIF}
{$ENDIF}

{:@abstract(OpenSSL support)

This unit is Pascal interface to OpenSSL library (used by @link(ssl_openssl) unit).
OpenSSL is loaded dynamicly on-demand. If this library is not found in system,
requested OpenSSL function just return errorcode.
}
unit ssl_openssl_lib;

interface

{$IFDEF IOS}
{$DEFINE STATIC}
{$ENDIF}

uses
  SysUtils, synabyte,
{$IFDEF CIL}
  System.Runtime.InteropServices,
  System.Text,
{$ENDIF}
  Classes,
  synafpc
{$IFDEF MSWINDOWS}
  , Windows
{$ELSE}
  {$IFDEF FPC}
   {$IFDEF UNIX}
  , BaseUnix
   {$ENDIF UNIX}
  {$ENDIF}
{$ENDIF};

const
{$IFDEF CIL}
  {$IFDEF LINUX}
  DLLSSLName = 'libssl.so';
  DLLUtilName = 'libcrypto.so';
  {$ELSE}
  DLLSSLName = 'ssleay32.dll';
  DLLUtilName = 'libeay32.dll';
  {$ENDIF}
{$ELSE}
{$IFDEF MSWINDOWS}
  DLLSSLName  = 'ssleay32.dll';
  DLLSSLName2 = 'libssl32.dll';
  DLLUtilName = 'libeay32.dll';
{$ENDIF}
  {$IFDEF MACOS}
    {$IFDEF IOS}
      DLLSSLName  = 'libssl.a';
      DLLUtilName = 'libcrypto.a';
    {$ELSE}
     DLLSSLName  = 'libssl.dylib';
     DLLUtilName = 'libcrypto.dylib';
   {$ENDIF}
  {$ENDIF}
  {$IFDEF ANDROID}
    DLLSSLName = 'libssl.so';
    DLLUtilName = 'libcrypto.so';
  {$ENDIF}
{$ENDIF}

type
{$IFDEF CIL}
  SslPtr = IntPtr;
{$ELSE}
  SslPtr = Pointer;
{$ENDIF}
  PSslPtr = ^SslPtr;
  PSSL_CTX = SslPtr;
  PSSL = SslPtr;
  PSSL_METHOD = SslPtr;
  PX509 = SslPtr;
  PX509_NAME = SslPtr;
  PEVP_MD	= SslPtr;
  PInteger = ^Integer;
  PBIO_METHOD = SslPtr;
  PBIO = SslPtr;
  EVP_PKEY = SslPtr;
  PRSA = SslPtr;
  PASN1_UTCTIME = SslPtr;
  PASN1_INTEGER = SslPtr;
  PPasswdCb = SslPtr;
  PFunction = procedure;
  PSTACK = SslPtr; {pf}
  TSkPopFreeFunc = procedure(p:SslPtr); cdecl; {pf}
  TX509Free = procedure(x: PX509); cdecl; {pf}

  DES_cblock = array[0..7] of Byte;
  PDES_cblock = ^DES_cblock;
  des_ks_struct = packed record
    ks: DES_cblock;
    weak_key: Integer;
  end;
  des_key_schedule = array[1..16] of des_ks_struct;

const
  EVP_MAX_MD_SIZE = 16 + 20;

  SSL_ERROR_NONE = 0;
  SSL_ERROR_SSL = 1;
  SSL_ERROR_WANT_READ = 2;
  SSL_ERROR_WANT_WRITE = 3;
  SSL_ERROR_WANT_X509_LOOKUP = 4;
  SSL_ERROR_SYSCALL = 5; //look at error stack/return value/errno
  SSL_ERROR_ZERO_RETURN = 6;
  SSL_ERROR_WANT_CONNECT = 7;
  SSL_ERROR_WANT_ACCEPT = 8;

  SSL_OP_NO_SSLv2 = $01000000;
  SSL_OP_NO_SSLv3 = $02000000;
  SSL_OP_NO_TLSv1 = $04000000;
  SSL_OP_ALL = $000FFFFF;
  SSL_VERIFY_NONE = $00;
  SSL_VERIFY_PEER = $01;

  OPENSSL_DES_DECRYPT = 0;
  OPENSSL_DES_ENCRYPT = 1;

  X509_V_OK =	0;
  X509_V_ILLEGAL = 1;
  X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT = 2;
  X509_V_ERR_UNABLE_TO_GET_CRL = 3;
  X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE = 4;
  X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE = 5;
  X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY = 6;
  X509_V_ERR_CERT_SIGNATURE_FAILURE = 7;
  X509_V_ERR_CRL_SIGNATURE_FAILURE = 8;
  X509_V_ERR_CERT_NOT_YET_VALID = 9;
  X509_V_ERR_CERT_HAS_EXPIRED = 10;
  X509_V_ERR_CRL_NOT_YET_VALID = 11;
  X509_V_ERR_CRL_HAS_EXPIRED = 12;
  X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD = 13;
  X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD = 14;
  X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD = 15;
  X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD = 16;
  X509_V_ERR_OUT_OF_MEM = 17;
  X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT = 18;
  X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN = 19;
  X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 20;
  X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE = 21;
  X509_V_ERR_CERT_CHAIN_TOO_LONG = 22;
  X509_V_ERR_CERT_REVOKED = 23;
  X509_V_ERR_INVALID_CA = 24;
  X509_V_ERR_PATH_LENGTH_EXCEEDED = 25;
  X509_V_ERR_INVALID_PURPOSE = 26;
  X509_V_ERR_CERT_UNTRUSTED = 27;
  X509_V_ERR_CERT_REJECTED = 28;
  //These are 'informational' when looking for issuer cert
  X509_V_ERR_SUBJECT_ISSUER_MISMATCH = 29;
  X509_V_ERR_AKID_SKID_MISMATCH = 30;
  X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH = 31;
  X509_V_ERR_KEYUSAGE_NO_CERTSIGN = 32;
  X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER = 33;
  X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION = 34;
  //The application is not happy
  X509_V_ERR_APPLICATION_VERIFICATION = 50;

  SSL_FILETYPE_ASN1	= 2;
  SSL_FILETYPE_PEM = 1;
  EVP_PKEY_RSA = 6;

  SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;
  TLSEXT_NAMETYPE_host_name = 0;

var
  SSLLibHandle: TLibHandle = 0;
  SSLUtilHandle: TLibHandle = 0;
  SSLLibFile: string = '';
  SSLUtilFile: string = '';

{$IFDEF CIL}
  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_get_error')]
    function SslGetError(s: PSSL; ret_code: Integer): Integer; external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_library_init')]
    function SslLibraryInit: Integer; external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_load_error_strings')]
    procedure SslLoadErrorStrings; external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_CTX_set_cipher_list')]
    function SslCtxSetCipherList(arg0: PSSL_CTX; var str: String): Integer; external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_CTX_new')]
    function SslCtxNew(meth: PSSL_METHOD):PSSL_CTX;  external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_CTX_free')]
    procedure SslCtxFree (arg0: PSSL_CTX);   external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_set_fd')]
    function SslSetFd(s: PSSL; fd: Integer):Integer;    external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSLv2_method')]
    function SslMethodV2 : PSSL_METHOD; external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSLv3_method')]
    function SslMethodV3 : PSSL_METHOD;  external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'TLSv1_method')]
    function SslMethodTLSV1:PSSL_METHOD;  external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSLv23_method')]
    function SslMethodV23 : PSSL_METHOD; external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_CTX_use_PrivateKey')]
    function SslCtxUsePrivateKey(ctx: PSSL_CTX; pkey: SslPtr):Integer;  external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_CTX_use_PrivateKey_ASN1')]
    function SslCtxUsePrivateKeyASN1(pk: integer; ctx: PSSL_CTX; d: String; len: integer):Integer;  external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_CTX_use_RSAPrivateKey_file')]
    function SslCtxUsePrivateKeyFile(ctx: PSSL_CTX; const _file: String; _type: Integer):Integer;  external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_CTX_use_certificate')]
    function SslCtxUseCertificate(ctx: PSSL_CTX; x: SslPtr):Integer; external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_CTX_use_certificate_ASN1')]
    function SslCtxUseCertificateASN1(ctx: PSSL_CTX; len: integer; d: String):Integer; external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_CTX_use_certificate_file')]
    function SslCtxUseCertificateFile(ctx: PSSL_CTX; const _file: String; _type: Integer):Integer;external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_CTX_use_certificate_chain_file')]
    function SslCtxUseCertificateChainFile(ctx: PSSL_CTX; const _file: String):Integer;external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_CTX_check_private_key')]
    function SslCtxCheckPrivateKeyFile(ctx: PSSL_CTX):Integer; external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_CTX_set_default_passwd_cb')]
    procedure SslCtxSetDefaultPasswdCb(ctx: PSSL_CTX; cb: PPasswdCb); external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_CTX_set_default_passwd_cb_userdata')]
    procedure SslCtxSetDefaultPasswdCbUserdata(ctx: PSSL_CTX; u: IntPtr); external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_CTX_load_verify_locations')]
    function SslCtxLoadVerifyLocations(ctx: PSSL_CTX; CAfile: string; CApath: String):Integer; external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_CTX_ctrl')]
    function SslCtxCtrl(ctx: PSSL_CTX; cmd: integer; larg: integer; parg: IntPtr): integer; external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_new')]
    function SslNew(ctx: PSSL_CTX):PSSL;  external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_free')]
    procedure SslFree(ssl: PSSL); external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_accept')]
    function SslAccept(ssl: PSSL):Integer; external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_connect')]
    function SslConnect(ssl: PSSL):Integer; external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_shutdown')]
    function SslShutdown(s: PSSL):Integer;  external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_read')]
    function SslRead(ssl: PSSL; buf: StringBuilder; num: Integer):Integer; external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_peek')]
    function SslPeek(ssl: PSSL; buf: StringBuilder; num: Integer):Integer; external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_write')]
    function SslWrite(ssl: PSSL; buf: String; num: Integer):Integer; external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_pending')]
    function SslPending(ssl: PSSL):Integer; external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_get_version')]
    function SslGetVersion(ssl: PSSL):String; external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_get_peer_certificate')]
    function SslGetPeerCertificate(s: PSSL):PX509; external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_CTX_set_verify')]
    procedure SslCtxSetVerify(ctx: PSSL_CTX; mode: Integer; arg2: PFunction); external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_get_current_cipher')]
    function SSLGetCurrentCipher(s: PSSL): SslPtr;  external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_CIPHER_get_name')]
    function SSLCipherGetName(c: SslPtr):String; external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_CIPHER_get_bits')]
    function SSLCipherGetBits(c: SslPtr; var alg_bits: Integer):Integer;  external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_get_verify_result')]
    function SSLGetVerifyResult(ssl: PSSL):Integer;external;

  [DllImport(DLLSSLName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'SSL_ctrl')]
    function SslCtrl(ssl: PSSL; cmd: integer; larg: integer; parg: IntPtr): integer; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'X509_new')]
    function X509New: PX509; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'X509_free')]
    procedure X509Free(x: PX509); external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'X509_NAME_oneline')]
    function X509NameOneline(a: PX509_NAME; buf: StringBuilder; size: Integer): String; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'X509_get_subject_name')]
    function X509GetSubjectName(a: PX509):PX509_NAME; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'X509_get_issuer_name')]
    function X509GetIssuerName(a: PX509):PX509_NAME;  external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'X509_NAME_hash')]
    function X509NameHash(x: PX509_NAME):Cardinal;   external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'X509_digest')]
    function X509Digest (data: PX509; _type: PEVP_MD; md: StringBuilder; var len: Integer):Integer; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'X509_set_version')]
    function X509SetVersion(x: PX509; version: integer): integer; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'X509_set_pubkey')]
    function X509SetPubkey(x: PX509; pkey: EVP_PKEY): integer; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'X509_set_issuer_name')]
    function X509SetIssuerName(x: PX509; name: PX509_NAME): integer; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'X509_NAME_add_entry_by_txt')]
    function X509NameAddEntryByTxt(name: PX509_NAME; field: string; _type: integer;
      bytes: string; len, loc, _set: integer): integer; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'X509_sign')]
    function X509Sign(x: PX509; pkey: EVP_PKEY; const md: PEVP_MD): integer; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'X509_print')]
    function X509print(b: PBIO; a: PX509): integer; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'X509_gmtime_adj')]
    function X509GmtimeAdj(s: PASN1_UTCTIME; adj: integer): PASN1_UTCTIME; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'X509_set_notBefore')]
    function X509SetNotBefore(x: PX509; tm: PASN1_UTCTIME): integer; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'X509_set_notAfter')]
    function X509SetNotAfter(x: PX509; tm: PASN1_UTCTIME): integer; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'X509_get_serialNumber')]
    function X509GetSerialNumber(x: PX509): PASN1_INTEGER; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'EVP_PKEY_new')]
    function EvpPkeyNew: EVP_PKEY; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'EVP_PKEY_free')]
    procedure EvpPkeyFree(pk: EVP_PKEY); external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'EVP_PKEY_assign')]
    function EvpPkeyAssign(pkey: EVP_PKEY; _type: integer; key: Prsa): integer; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'EVP_get_digestbyname')]
    function EvpGetDigestByName(Name: String): PEVP_MD; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'EVP_cleanup')]
    procedure EVPcleanup; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'SSLeay_version')]
    function SSLeayversion(t: integer): String; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'ERR_error_string_n')]
    procedure ErrErrorString(e: integer; buf: StringBuilder; len: integer); external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'ERR_get_error')]
    function ErrGetError: integer; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'ERR_clear_error')]
    procedure ErrClearError; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'ERR_free_strings')]
    procedure ErrFreeStrings; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'ERR_remove_state')]
    procedure ErrRemoveState(pid: integer); external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'OPENSSL_add_all_algorithms_noconf')]
    procedure OPENSSLaddallalgorithms; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'CRYPTO_cleanup_all_ex_data')]
    procedure CRYPTOcleanupAllExData; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'RAND_screen')]
    procedure RandScreen; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'BIO_new')]
    function BioNew(b: PBIO_METHOD): PBIO; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'BIO_free_all')]
    procedure BioFreeAll(b: PBIO); external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'BIO_s_mem')]
    function BioSMem: PBIO_METHOD; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'BIO_ctrl_pending')]
    function BioCtrlPending(b: PBIO): integer; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'BIO_read')]
    function BioRead(b: PBIO; Buf: StringBuilder; Len: integer): integer; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'BIO_write')]
    function BioWrite(b: PBIO; var Buf: String; Len: integer): integer; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'd2i_PKCS12_bio')]
    function d2iPKCS12bio(b:PBIO; Pkcs12: SslPtr): SslPtr; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'PKCS12_parse')]
    function PKCS12parse(p12: SslPtr; pass: string; var pkey, cert, ca: SslPtr): integer; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'PKCS12_free')]
    procedure PKCS12free(p12: SslPtr); external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'RSA_generate_key')]
    function RsaGenerateKey(bits, e: integer; callback: PFunction; cb_arg: SslPtr): PRSA; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'ASN1_UTCTIME_new')]
    function Asn1UtctimeNew: PASN1_UTCTIME; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'ASN1_UTCTIME_free')]
    procedure Asn1UtctimeFree(a: PASN1_UTCTIME); external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'ASN1_INTEGER_set')]
    function Asn1IntegerSet(a: PASN1_INTEGER; v: integer): integer; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'i2d_X509_bio')]
    function i2dX509bio(b: PBIO; x: PX509): integer; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint =  'i2d_PrivateKey_bio')]
    function i2dPrivateKeyBio(b: PBIO; pkey: EVP_PKEY): integer; external;

  // 3DES functions
  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'DES_set_odd_parity')]
    procedure DESsetoddparity(Key: des_cblock); external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'DES_set_key_checked')]
    function DESsetkeychecked(key: des_cblock; schedule: des_key_schedule): Integer; external;

  [DllImport(DLLUtilName, CharSet = CharSet.Ansi,
    SetLastError = False, CallingConvention= CallingConvention.cdecl,
    EntryPoint = 'DES_ecb_encrypt')]
    procedure DESecbencrypt(Input: des_cblock; output: des_cblock; ks: des_key_schedule; enc: Integer); external;

{$ELSE}
// libssl.dll
  function SslGetError(s: PSSL; ret_code: Integer):Integer;
  function SslLibraryInit:Integer;
  procedure SslLoadErrorStrings;
//  function SslCtxSetCipherList(arg0: PSSL_CTX; str: PChar):Integer;
  function SslCtxSetCipherList(arg0: PSSL_CTX; str: PByte):Integer;
  function SslCtxNew(meth: PSSL_METHOD):PSSL_CTX;
  procedure SslCtxFree(arg0: PSSL_CTX);
  function SslSetFd(s: PSSL; fd: Integer):Integer;
  function SslMethodV2:PSSL_METHOD;
  function SslMethodV3:PSSL_METHOD;
  function SslMethodTLSV1:PSSL_METHOD;
  function SslMethodV23:PSSL_METHOD;
  function SslCtxUsePrivateKey(ctx: PSSL_CTX; pkey: SslPtr):Integer;
  function SslCtxUsePrivateKeyASN1(pk: integer; ctx: PSSL_CTX; d: TSynaBytes; len: integer):Integer;
//  function SslCtxUsePrivateKeyFile(ctx: PSSL_CTX; const _file: PChar; _type: Integer):Integer;
  function SslCtxUsePrivateKeyFile(ctx: PSSL_CTX; const _file: TSynaBytes; _type: Integer):Integer;
  function SslCtxUseCertificate(ctx: PSSL_CTX; x: SslPtr):Integer;
  function SslCtxUseCertificateASN1(ctx: PSSL_CTX; len: integer; d: TSynaBytes):Integer;
  function SslCtxUseCertificateFile(ctx: PSSL_CTX; const _file: TSynaBytes; _type: Integer):Integer;
//  function SslCtxUseCertificateChainFile(ctx: PSSL_CTX; const _file: PChar):Integer;
  function SslCtxUseCertificateChainFile(ctx: PSSL_CTX; const _file: TSynaBytes):Integer;
  function SslCtxCheckPrivateKeyFile(ctx: PSSL_CTX):Integer;
  procedure SslCtxSetDefaultPasswdCb(ctx: PSSL_CTX; cb: PPasswdCb);
  procedure SslCtxSetDefaultPasswdCbUserdata(ctx: PSSL_CTX; u: SslPtr);
//  function SslCtxLoadVerifyLocations(ctx: PSSL_CTX; const CAfile: PChar; const CApath: PChar):Integer;
  function SslCtxLoadVerifyLocations(ctx: PSSL_CTX; const CAfile: TSynaBytes; const CApath: TSynaBytes):Integer;
  function SslCtxCtrl(ctx: PSSL_CTX; cmd: integer; larg: integer; parg: SslPtr): integer;
  function SslNew(ctx: PSSL_CTX):PSSL;
  procedure SslFree(ssl: PSSL);
  function SslAccept(ssl: PSSL):Integer;
  function SslConnect(ssl: PSSL):Integer;
  function SslShutdown(ssl: PSSL):Integer;
  function SslRead(ssl: PSSL; buf: SslPtr; num: Integer):Integer;
  function SslPeek(ssl: PSSL; buf: SslPtr; num: Integer):Integer;
  function SslWrite(ssl: PSSL; buf: SslPtr; num: Integer):Integer;
  function SslPending(ssl: PSSL):Integer;
  function SslGetVersion(ssl: PSSL):String;
  function SslGetPeerCertificate(ssl: PSSL):PX509;
  procedure SslCtxSetVerify(ctx: PSSL_CTX; mode: Integer; arg2: PFunction);
  function SSLGetCurrentCipher(s: PSSL):SslPtr;
  function SSLCipherGetName(c: SslPtr): String;
  function SSLCipherGetBits(c: SslPtr; var alg_bits: Integer):Integer;
  function SSLGetVerifyResult(ssl: PSSL):Integer;
  function SSLCtrl(ssl: PSSL; cmd: integer; larg: integer; parg: SslPtr):Integer;

// libeay.dll
  function X509New: PX509;
  procedure X509Free(x: PX509);
  function X509NameOneline(a: PX509_NAME; buf: PByte; size: Integer): String;
  function X509GetSubjectName(a: PX509):PX509_NAME;
  function X509GetIssuerName(a: PX509):PX509_NAME;
  function X509NameHash(x: PX509_NAME):Cardinal;
//  function SslX509Digest(data: PX509; _type: PEVP_MD; md: PChar; len: PInteger):Integer;
  function X509Digest(data: PX509; _type: PEVP_MD; md: TSynaBytes; var len: Integer):Integer;
  function X509print(b: PBIO; a: PX509): integer;
  function X509SetVersion(x: PX509; version: integer): integer;
  function X509SetPubkey(x: PX509; pkey: EVP_PKEY): integer;
  function X509SetIssuerName(x: PX509; name: PX509_NAME): integer;
  function X509NameAddEntryByTxt(name: PX509_NAME; field: TSynaBytes; _type: integer;
    bytes: TSynaBytes; len, loc, _set: integer): integer;
  function X509Sign(x: PX509; pkey: EVP_PKEY; const md: PEVP_MD): integer;
  function X509GmtimeAdj(s: PASN1_UTCTIME; adj: integer): PASN1_UTCTIME;
  function X509SetNotBefore(x: PX509; tm: PASN1_UTCTIME): integer;
  function X509SetNotAfter(x: PX509; tm: PASN1_UTCTIME): integer;
  function X509GetSerialNumber(x: PX509): PASN1_INTEGER;
  function EvpPkeyNew: EVP_PKEY;
  procedure EvpPkeyFree(pk: EVP_PKEY);
  function EvpPkeyAssign(pkey: EVP_PKEY; _type: integer; key: Prsa): integer;
  function EvpGetDigestByName(Name: TSynaBytes): PEVP_MD;
  procedure EVPcleanup;
//  function ErrErrorString(e: integer; buf: PChar): PChar;
  function SSLeayversion(t: integer): string;
  procedure ErrErrorString(e: integer; var buf: TSynaBytes; len: integer);
  function ErrGetError: integer;
  procedure ErrClearError;
  procedure ErrFreeStrings;
  procedure ErrRemoveState(pid: integer);
  procedure OPENSSLaddallalgorithms;
  procedure CRYPTOcleanupAllExData;
  procedure RandScreen;
  function BioNew(b: PBIO_METHOD): PBIO;
  procedure BioFreeAll(b: PBIO);
  function BioSMem: PBIO_METHOD;
  function BioCtrlPending(b: PBIO): integer;
  function BioRead(b: PBIO; Buf: PByte; Len: integer): integer;
  function BioWrite(b: PBIO; Buf: PByte; Len: integer): integer;
  function d2iPKCS12bio(b:PBIO; Pkcs12: SslPtr): SslPtr;
  function PKCS12parse(p12: SslPtr; pass: TSynaBytes; var pkey, cert, ca: SslPtr): integer;
  procedure PKCS12free(p12: SslPtr);
  function RsaGenerateKey(bits, e: integer; callback: PFunction; cb_arg: SslPtr): PRSA;
  function Asn1UtctimeNew: PASN1_UTCTIME;
  procedure Asn1UtctimeFree(a: PASN1_UTCTIME);
  function Asn1IntegerSet(a: PASN1_INTEGER; v: integer): integer;
  function Asn1IntegerGet(a: PASN1_INTEGER): integer; {pf}
  function i2dX509bio(b: PBIO; x: PX509): integer;
  function d2iX509bio(b:PBIO; x:PX509):  PX509;    {pf}
  function PEMReadBioX509(b:PBIO; {var x:PX509;}x:PSslPtr; callback:PFunction; cb_arg: SslPtr):  PX509;    {pf}
  procedure SkX509PopFree(st: PSTACK; func: TSkPopFreeFunc); {pf}


  function i2dPrivateKeyBio(b: PBIO; pkey: EVP_PKEY): integer;

  // 3DES functions
  procedure DESsetoddparity(Key: des_cblock);
  function DESsetkeychecked(key: des_cblock; schedule: des_key_schedule): Integer;
  procedure DESecbencrypt(Input: des_cblock; output: des_cblock; ks: des_key_schedule; enc: Integer);

{$ENDIF}

function IsSSLloaded: Boolean;
function InitSSLInterface: Boolean;
function DestroySSLInterface: Boolean;

var
  _X509Free: TX509Free = nil; {pf}

implementation

uses
{$IFDEF OS2}
  Sockets,
{$ENDIF OS2}
  SyncObjs;

{$IFNDEF CIL}

{$IFNDEF STATIC}
type
// libssl.dll
  TSslGetError = function(s: PSSL; ret_code: Integer):Integer; cdecl;
  TSslLibraryInit = function:Integer; cdecl;
  TSslLoadErrorStrings = procedure; cdecl;
  TSslCtxSetCipherList = function(arg0: PSSL_CTX; str: PByte):Integer; cdecl;
  TSslCtxNew = function(meth: PSSL_METHOD):PSSL_CTX; cdecl;
  TSslCtxFree = procedure(arg0: PSSL_CTX); cdecl;
  TSslSetFd = function(s: PSSL; fd: Integer):Integer; cdecl;
  TSslMethodV2 = function:PSSL_METHOD; cdecl;
  TSslMethodV3 = function:PSSL_METHOD; cdecl;
  TSslMethodTLSV1 = function:PSSL_METHOD; cdecl;
  TSslMethodV23 = function:PSSL_METHOD; cdecl;
  TSslCtxUsePrivateKey = function(ctx: PSSL_CTX; pkey: sslptr):Integer; cdecl;
  TSslCtxUsePrivateKeyASN1 = function(pk: integer; ctx: PSSL_CTX; d: sslptr; len: integer):Integer; cdecl;
  TSslCtxUsePrivateKeyFile = function(ctx: PSSL_CTX; const _file: PByte; _type: Integer):Integer; cdecl;
  TSslCtxUseCertificate = function(ctx: PSSL_CTX; x: SslPtr):Integer; cdecl;
  TSslCtxUseCertificateASN1 = function(ctx: PSSL_CTX; len: Integer; d: SslPtr):Integer; cdecl;
  TSslCtxUseCertificateFile = function(ctx: PSSL_CTX; const _file: PByte; _type: Integer):Integer; cdecl;
  TSslCtxUseCertificateChainFile = function(ctx: PSSL_CTX; const _file: PByte):Integer; cdecl;
  TSslCtxCheckPrivateKeyFile = function(ctx: PSSL_CTX):Integer; cdecl;
  TSslCtxSetDefaultPasswdCb = procedure(ctx: PSSL_CTX; cb: SslPtr); cdecl;
  TSslCtxSetDefaultPasswdCbUserdata = procedure(ctx: PSSL_CTX; u: SslPtr); cdecl;
  TSslCtxLoadVerifyLocations = function(ctx: PSSL_CTX; const CAfile: PByte; const CApath: PByte):Integer; cdecl;
  TSslCtxCtrl = function(ctx: PSSL_CTX; cmd: integer; larg: integer; parg: SslPtr): integer; cdecl;
  TSslNew = function(ctx: PSSL_CTX):PSSL; cdecl;
  TSslFree = procedure(ssl: PSSL); cdecl;
  TSslAccept = function(ssl: PSSL):Integer; cdecl;
  TSslConnect = function(ssl: PSSL):Integer; cdecl;
  TSslShutdown = function(ssl: PSSL):Integer; cdecl;
  TSslRead = function(ssl: PSSL; buf: PByte; num: Integer):Integer; cdecl;
  TSslPeek = function(ssl: PSSL; buf: PByte; num: Integer):Integer; cdecl;
  TSslWrite = function(ssl: PSSL; const buf: PByte; num: Integer):Integer; cdecl;
  TSslPending = function(ssl: PSSL):Integer; cdecl;
  TSslGetVersion = function(ssl: PSSL):PByte; cdecl;
  TSslGetPeerCertificate = function(ssl: PSSL):PX509; cdecl;
  TSslCtxSetVerify = procedure(ctx: PSSL_CTX; mode: Integer; arg2: SslPtr); cdecl;
  TSSLGetCurrentCipher = function(s: PSSL):SslPtr; cdecl;
  TSSLCipherGetName = function(c: Sslptr):PByte; cdecl;
  TSSLCipherGetBits = function(c: SslPtr; alg_bits: PInteger):Integer; cdecl;
  TSSLGetVerifyResult = function(ssl: PSSL):Integer; cdecl;
  TSSLCtrl = function(ssl: PSSL; cmd: integer; larg: integer; parg: SslPtr):Integer; cdecl;

// libeay.dll
  TX509New = function: PX509; cdecl;
  TX509NameOneline = function(a: PX509_NAME; buf: PByte; size: Integer):PByte; cdecl;
  TX509GetSubjectName = function(a: PX509):PX509_NAME; cdecl;
  TX509GetIssuerName = function(a: PX509):PX509_NAME; cdecl;
  TX509NameHash = function(x: PX509_NAME):Cardinal; cdecl;
  TX509Digest = function(data: PX509; _type: PEVP_MD; md: PByte; len: PInteger):Integer; cdecl;
  TX509print = function(b: PBIO; a: PX509): integer; cdecl;
  TX509SetVersion = function(x: PX509; version: integer): integer; cdecl;
  TX509SetPubkey = function(x: PX509; pkey: EVP_PKEY): integer; cdecl;
  TX509SetIssuerName = function(x: PX509; name: PX509_NAME): integer; cdecl;
  TX509NameAddEntryByTxt = function(name: PX509_NAME; field: PByte; _type: integer;
    bytes: PByte; len, loc, _set: integer): integer; cdecl;
  TX509Sign = function(x: PX509; pkey: EVP_PKEY; const md: PEVP_MD): integer; cdecl;
  TX509GmtimeAdj = function(s: PASN1_UTCTIME; adj: integer): PASN1_UTCTIME; cdecl;
  TX509SetNotBefore = function(x: PX509; tm: PASN1_UTCTIME): integer; cdecl;
  TX509SetNotAfter = function(x: PX509; tm: PASN1_UTCTIME): integer; cdecl;
  TX509GetSerialNumber = function(x: PX509): PASN1_INTEGER; cdecl;
  TEvpPkeyNew = function: EVP_PKEY; cdecl;
  TEvpPkeyFree = procedure(pk: EVP_PKEY); cdecl;
  TEvpPkeyAssign = function(pkey: EVP_PKEY; _type: integer; key: Prsa): integer; cdecl;
  TEvpGetDigestByName = function(Name: PByte): PEVP_MD; cdecl;
  TEVPcleanup = procedure; cdecl;
  TSSLeayversion = function(t: integer): PByte; cdecl;
  TErrErrorString = procedure(e: integer; buf: PByte; len: integer); cdecl;
  TErrGetError = function: integer; cdecl;
  TErrClearError = procedure; cdecl;
  TErrFreeStrings = procedure; cdecl;
  TErrRemoveState = procedure(pid: integer); cdecl;
  TOPENSSLaddallalgorithms = procedure; cdecl;
  TCRYPTOcleanupAllExData = procedure; cdecl;
  TRandScreen = procedure; cdecl;
  TBioNew = function(b: PBIO_METHOD): PBIO; cdecl;
  TBioFreeAll = procedure(b: PBIO); cdecl;
  TBioSMem = function: PBIO_METHOD; cdecl;
  TBioCtrlPending = function(b: PBIO): integer; cdecl;
  TBioRead = function(b: PBIO; Buf: PByte; Len: integer): integer; cdecl;
  TBioWrite = function(b: PBIO; Buf: PByte; Len: integer): integer; cdecl;
  Td2iPKCS12bio = function(b:PBIO; Pkcs12: SslPtr): SslPtr; cdecl;
  TPKCS12parse = function(p12: SslPtr; pass: PByte; var pkey, cert, ca: SslPtr): integer; cdecl;
  TPKCS12free = procedure(p12: SslPtr); cdecl;
  TRsaGenerateKey = function(bits, e: integer; callback: PFunction; cb_arg: SslPtr): PRSA; cdecl;
  TAsn1UtctimeNew = function: PASN1_UTCTIME; cdecl;
  TAsn1UtctimeFree = procedure(a: PASN1_UTCTIME); cdecl;
  TAsn1IntegerSet = function(a: PASN1_INTEGER; v: integer): integer; cdecl;
  TAsn1IntegerGet = function(a: PASN1_INTEGER): integer; cdecl; {pf}
  Ti2dX509bio = function(b: PBIO; x: PX509): integer; cdecl;
  Td2iX509bio = function(b:PBIO;  x:PX509):   PX509;   cdecl; {pf}
  TPEMReadBioX509 = function(b:PBIO;  {var x:PX509;}x:PSslPtr; callback:PFunction; cb_arg:SslPtr): PX509;   cdecl; {pf}
  TSkX509PopFree = procedure(st: PSTACK; func: TSkPopFreeFunc); cdecl; {pf}
  Ti2dPrivateKeyBio= function(b: PBIO; pkey: EVP_PKEY): integer; cdecl;

  // 3DES functions
  TDESsetoddparity = procedure(Key: des_cblock); cdecl;
  TDESsetkeychecked = function(key: des_cblock; schedule: des_key_schedule): Integer; cdecl;
  TDESecbencrypt = procedure(Input: des_cblock; output: des_cblock; ks: des_key_schedule; enc: Integer); cdecl;
  //thread lock functions
  TCRYPTOnumlocks = function: integer; cdecl;
  TCRYPTOSetLockingCallback = procedure(cb: Sslptr); cdecl;

var
// libssl.dll
  _SslGetError: TSslGetError = nil;
  _SslLibraryInit: TSslLibraryInit = nil;
  _SslLoadErrorStrings: TSslLoadErrorStrings = nil;
  _SslCtxSetCipherList: TSslCtxSetCipherList = nil;
  _SslCtxNew: TSslCtxNew = nil;
  _SslCtxFree: TSslCtxFree = nil;
  _SslSetFd: TSslSetFd = nil;
  _SslMethodV2: TSslMethodV2 = nil;
  _SslMethodV3: TSslMethodV3 = nil;
  _SslMethodTLSV1: TSslMethodTLSV1 = nil;
  _SslMethodV23: TSslMethodV23 = nil;
  _SslCtxUsePrivateKey: TSslCtxUsePrivateKey = nil;
  _SslCtxUsePrivateKeyASN1: TSslCtxUsePrivateKeyASN1 = nil;
  _SslCtxUsePrivateKeyFile: TSslCtxUsePrivateKeyFile = nil;
  _SslCtxUseCertificate: TSslCtxUseCertificate = nil;
  _SslCtxUseCertificateASN1: TSslCtxUseCertificateASN1 = nil;
  _SslCtxUseCertificateFile: TSslCtxUseCertificateFile = nil;
  _SslCtxUseCertificateChainFile: TSslCtxUseCertificateChainFile = nil;
  _SslCtxCheckPrivateKeyFile: TSslCtxCheckPrivateKeyFile = nil;
  _SslCtxSetDefaultPasswdCb: TSslCtxSetDefaultPasswdCb = nil;
  _SslCtxSetDefaultPasswdCbUserdata: TSslCtxSetDefaultPasswdCbUserdata = nil;
  _SslCtxLoadVerifyLocations: TSslCtxLoadVerifyLocations = nil;
  _SslCtxCtrl: TSslCtxCtrl = nil;
  _SslNew: TSslNew = nil;
  _SslFree: TSslFree = nil;
  _SslAccept: TSslAccept = nil;
  _SslConnect: TSslConnect = nil;
  _SslShutdown: TSslShutdown = nil;
  _SslRead: TSslRead = nil;
  _SslPeek: TSslPeek = nil;
  _SslWrite: TSslWrite = nil;
  _SslPending: TSslPending = nil;
  _SslGetVersion: TSslGetVersion = nil;
  _SslGetPeerCertificate: TSslGetPeerCertificate = nil;
  _SslCtxSetVerify: TSslCtxSetVerify = nil;
  _SSLGetCurrentCipher: TSSLGetCurrentCipher = nil;
  _SSLCipherGetName: TSSLCipherGetName = nil;
  _SSLCipherGetBits: TSSLCipherGetBits = nil;
  _SSLGetVerifyResult: TSSLGetVerifyResult = nil;
  _SSLCtrl: TSSLCtrl = nil;

// libeay.dll
  _X509New: TX509New = nil;
  _X509NameOneline: TX509NameOneline = nil;
  _X509GetSubjectName: TX509GetSubjectName = nil;
  _X509GetIssuerName: TX509GetIssuerName = nil;
  _X509NameHash: TX509NameHash = nil;
  _X509Digest: TX509Digest = nil;
  _X509print: TX509print = nil;
  _X509SetVersion: TX509SetVersion = nil;
  _X509SetPubkey: TX509SetPubkey = nil;
  _X509SetIssuerName: TX509SetIssuerName = nil;
  _X509NameAddEntryByTxt: TX509NameAddEntryByTxt = nil;
  _X509Sign: TX509Sign = nil;
  _X509GmtimeAdj: TX509GmtimeAdj = nil;
  _X509SetNotBefore: TX509SetNotBefore = nil;
  _X509SetNotAfter: TX509SetNotAfter = nil;
  _X509GetSerialNumber: TX509GetSerialNumber = nil;
  _EvpPkeyNew: TEvpPkeyNew = nil;
  _EvpPkeyFree: TEvpPkeyFree = nil;
  _EvpPkeyAssign: TEvpPkeyAssign = nil;
  _EvpGetDigestByName: TEvpGetDigestByName = nil;
  _EVPcleanup: TEVPcleanup = nil;
  _SSLeayversion: TSSLeayversion = nil;
  _ErrErrorString: TErrErrorString = nil;
  _ErrGetError: TErrGetError = nil;
  _ErrClearError: TErrClearError = nil;
  _ErrFreeStrings: TErrFreeStrings = nil;
  _ErrRemoveState: TErrRemoveState = nil;
  _OPENSSLaddallalgorithms: TOPENSSLaddallalgorithms = nil;
  _CRYPTOcleanupAllExData: TCRYPTOcleanupAllExData = nil;
  _RandScreen: TRandScreen = nil;
  _BioNew: TBioNew = nil;
  _BioFreeAll: TBioFreeAll = nil;
  _BioSMem: TBioSMem = nil;
  _BioCtrlPending: TBioCtrlPending = nil;
  _BioRead: TBioRead = nil;
  _BioWrite: TBioWrite = nil;
  _d2iPKCS12bio: Td2iPKCS12bio = nil;
  _PKCS12parse: TPKCS12parse = nil;
  _PKCS12free: TPKCS12free = nil;
  _RsaGenerateKey: TRsaGenerateKey = nil;
  _Asn1UtctimeNew: TAsn1UtctimeNew = nil;
  _Asn1UtctimeFree: TAsn1UtctimeFree = nil;
  _Asn1IntegerSet: TAsn1IntegerSet = nil;
  _Asn1IntegerGet: TAsn1IntegerGet = nil; {pf}
  _i2dX509bio: Ti2dX509bio = nil;
  _d2iX509bio: Td2iX509bio = nil; {pf}
  _PEMReadBioX509: TPEMReadBioX509 = nil; {pf}
  _SkX509PopFree: TSkX509PopFree = nil; {pf}
  _i2dPrivateKeyBio: Ti2dPrivateKeyBio = nil;

  // 3DES functions
  _DESsetoddparity: TDESsetoddparity = nil;
  _DESsetkeychecked: TDESsetkeychecked = nil;
  _DESecbencrypt: TDESecbencrypt = nil;
  //thread lock functions
  _CRYPTOnumlocks: TCRYPTOnumlocks = nil;
  _CRYPTOSetLockingCallback: TCRYPTOSetLockingCallback = nil;
{$ELSE} //STATIC
// libssl.dll
   function _SslGetError(s: PSSL; ret_code: Integer):Integer; cdecl; external DLLSSLName name 'SSL_get_error';
  function _SslLibraryInit(): integer; cdecl; external DLLSSLName name 'SSL_library_init';
  procedure _SslLoadErrorStrings(); cdecl;external DLLSSLName name 'SSL_load_error_strings';
  function _SslCtxSetCipherList (arg0: PSSL_CTX; str: PByte):Integer; cdecl;external DLLSSLName name 'SSL_CTX_set_cipher_list';
  function _SslCtxNew (meth: PSSL_METHOD):PSSL_CTX; cdecl;external DLLSSLName name 'SSL_CTX_new';
  procedure _SslCtxFree(arg0: PSSL_CTX); cdecl;external DLLSSLName name 'SSL_CTX_free';
  function _SslSetFd (s: PSSL; fd: Integer):Integer; cdecl;external DLLSSLName name 'SSL_set_fd';
  function _SslMethodV2():PSSL_METHOD; cdecl;external DLLSSLName name 'SSLv2_method';
  function _SslMethodV3():PSSL_METHOD; cdecl;external DLLSSLName name 'SSLv3_method';
  function _SslMethodTLSV1:PSSL_METHOD; cdecl;external DLLSSLName name 'TLSv1_method';
  function _SslMethodV23:PSSL_METHOD; cdecl;external DLLSSLName name 'SSLv23_method';
  function _SslCtxUsePrivateKey (ctx: PSSL_CTX; pkey: sslptr):Integer; cdecl;external DLLSSLName name 'SSL_CTX_use_PrivateKey';
  function _SslCtxUsePrivateKeyASN1 (pk: integer; ctx: PSSL_CTX; d: sslptr; len: integer):Integer; cdecl;external DLLSSLName name 'SSL_CTX_use_PrivateKey_ASN1';
  function _SslCtxUsePrivateKeyFile (ctx: PSSL_CTX; const _file: PByte; _type: Integer):Integer; cdecl;external DLLSSLName name 'SSL_CTX_use_RSAPrivateKey_file';
  function _SslCtxUseCertificate (ctx: PSSL_CTX; x: SslPtr):Integer; cdecl;external DLLSSLName name 'SSL_CTX_use_certificate';
  function _SslCtxUseCertificateASN1 (ctx: PSSL_CTX; len: Integer; d: SslPtr):Integer; cdecl;external DLLSSLName name 'SSL_CTX_use_certificate_ASN1';
  function _SslCtxUseCertificateFile (ctx: PSSL_CTX; const _file: PByte; _type: Integer):Integer; cdecl;external DLLSSLName name 'SSL_CTX_use_certificate_file';
  function _SslCtxUseCertificateChainFile (ctx: PSSL_CTX; const _file: PByte):Integer; cdecl;external DLLSSLName name 'SSL_CTX_use_certificate_chain_file';
  function _SslCtxCheckPrivateKeyFile (ctx: PSSL_CTX):Integer; cdecl;external DLLSSLName name 'SSL_CTX_check_private_key';
  procedure _SslCtxSetDefaultPasswdCb(ctx: PSSL_CTX; cb: SslPtr); cdecl;external DLLSSLName name 'SSL_CTX_set_default_passwd_cb';
  procedure _SslCtxSetDefaultPasswdCbUserdata(ctx: PSSL_CTX; u: SslPtr); cdecl;external DLLSSLName name 'SSL_CTX_set_default_passwd_cb_userdata';
  function _SslCtxLoadVerifyLocations (ctx: PSSL_CTX; const CAfile: PByte; const CApath: PByte):Integer; cdecl;external DLLSSLName name 'SSL_CTX_load_verify_locations';
  function _SslCtxCtrl (ctx: PSSL_CTX; cmd: integer; larg: integer; parg: SslPtr): integer; cdecl;external DLLSSLName name 'SSL_CTX_ctrl';
  function _SslNew (ctx: PSSL_CTX):PSSL; cdecl;external DLLSSLName name 'SSL_new';
  procedure _SslFree(ssl: PSSL); cdecl;external DLLSSLName name 'SSL_free';
  function _SslAccept (ssl: PSSL):Integer; cdecl;external DLLSSLName name 'SSL_accept';
  function _SslConnect (ssl: PSSL):Integer; cdecl;external DLLSSLName name 'SSL_connect';
  function _SslShutdown (ssl: PSSL):Integer; cdecl;external DLLSSLName name 'SSL_shutdown';
  function _SslRead (ssl: PSSL; buf: PByte; num: Integer):Integer; cdecl;external DLLSSLName name 'SSL_read';
  function _SslPeek (ssl: PSSL; buf: PByte; num: Integer):Integer; cdecl;external DLLSSLName name 'SSL_peek';
  function _SslWrite (ssl: PSSL; const buf: PByte; num: Integer):Integer; cdecl;external DLLSSLName name 'SSL_write';
  function _SslPending (ssl: PSSL):Integer; cdecl;external DLLSSLName name 'SSL_pending';
  function _SslGetVersion (ssl: PSSL):PByte; cdecl;external DLLSSLName name 'SSL_get_version';
  function _SslGetPeerCertificate (ssl: PSSL):PX509; cdecl;external DLLSSLName name 'SSL_get_peer_certificate';
  procedure _SslCtxSetVerify(ctx: PSSL_CTX; mode: Integer; arg2: SslPtr); cdecl;external DLLSSLName name 'SSL_CTX_set_verify';
  function _SslGetCurrentCipher (s: PSSL):SslPtr; cdecl;external DLLSSLName name 'SSL_get_current_cipher';
  function _SslCipherGetName (c: Sslptr):PByte; cdecl;external DLLSSLName name 'SSL_CIPHER_get_name';
  function _SslCipherGetBits (c: SslPtr; alg_bits: PInteger):Integer; cdecl;external DLLSSLName name 'SSL_CIPHER_get_bits';
  function _SslGetVerifyResult (ssl: PSSL):Integer; cdecl;external DLLSSLName name 'SSL_get_verify_result';
  function _SslCtrl (ssl: PSSL; cmd: integer; larg: integer; parg: SslPtr):Integer; cdecl;external DLLSSLName name 'SSL_ctrl';

// libeay.dll
  function _X509New: PX509; cdecl;external DLLUtilName name 'X509_new';
  function _X509NameOneline(a: PX509_NAME; buf: PByte; size: Integer):PByte; cdecl;external DLLUtilName name 'X509_NAME_oneline';
  function _X509GetSubjectName(a: PX509):PX509_NAME; cdecl;external DLLUtilName name 'X509_get_subject_name';
  function _X509GetIssuerName(a: PX509):PX509_NAME; cdecl;external DLLUtilName name 'X509_get_issuer_name';
  function _X509NameHash(x: PX509_NAME):Cardinal; cdecl;external DLLUtilName name 'X509_NAME_hash';
  function _X509Digest(data: PX509; _type: PEVP_MD; md: PByte; len: PInteger):Integer; cdecl;external DLLUtilName name 'X509_digest';
  function _X509print(b: PBIO; a: PX509): integer; cdecl;external DLLUtilName name 'X509_print';
  function _X509SetVersion(x: PX509; version: integer): integer; cdecl;external DLLUtilName name 'X509_set_version';
  function _X509SetPubkey(x: PX509; pkey: EVP_PKEY): integer; cdecl;external DLLUtilName name 'X509_set_pubkey';
  function _X509SetIssuerName(x: PX509; name: PX509_NAME): integer; cdecl;external DLLUtilName name 'X509_set_issuer_name';
  function _X509NameAddEntryByTxt(name: PX509_NAME; field: PByte; _type: integer;
    bytes: PByte; len, loc, _set: integer): integer; cdecl;external DLLUtilName name 'X509_NAME_add_entry_by_txt';
  function _X509Sign(x: PX509; pkey: EVP_PKEY; const md: PEVP_MD): integer; cdecl;external DLLUtilName name 'X509_sign';
  function _X509GmtimeAdj(s: PASN1_UTCTIME; adj: integer): PASN1_UTCTIME; cdecl;external DLLUtilName name 'X509_gmtime_adj';
  function _X509SetNotBefore(x: PX509; tm: PASN1_UTCTIME): integer; cdecl;external DLLUtilName name 'X509_set_notBefore';
  function _X509SetNotAfter(x: PX509; tm: PASN1_UTCTIME): integer; cdecl;external DLLUtilName name 'X509_set_notAfter';
  function _X509GetSerialNumber(x: PX509): PASN1_INTEGER; cdecl;external DLLUtilName name 'X509_get_serialNumber';
  function _EvpPkeyNew: EVP_PKEY; cdecl;external DLLUtilName name 'EVP_PKEY_new';
  procedure _EvpPkeyFree(pk: EVP_PKEY); cdecl;external DLLUtilName name 'EVP_PKEY_free';
  function _EvpPkeyAssign(pkey: EVP_PKEY; _type: integer; key: Prsa): integer; cdecl;external DLLUtilName name 'EVP_PKEY_assign';
  function _EvpGetDigestByName(Name: PByte): PEVP_MD; cdecl;external DLLUtilName name 'EVP_get_digestbyname';
  procedure _EVPcleanup; cdecl;external DLLUtilName name 'EVP_cleanup';
  function _SSLeayversion(t: integer): PByte; cdecl;external DLLUtilName name 'SSLeay_version';
  procedure _ErrErrorString(e: integer; buf: PByte; len: integer); cdecl;external DLLUtilName name 'ERR_error_string_n';
  function _ErrGetError: integer; cdecl;external DLLUtilName name 'ERR_get_error';
  procedure _ErrClearError; cdecl;external DLLUtilName name 'ERR_clear_error';
  procedure _ErrFreeStrings; cdecl;external DLLUtilName name 'ERR_free_strings';
  procedure _ErrRemoveState(pid: integer); cdecl;external DLLUtilName name 'ERR_remove_state';
  procedure _OPENSSLaddallalgorithms; cdecl;external DLLUtilName name 'OPENSSL_add_all_algorithms_noconf';
  procedure _CRYPTOcleanupAllExData; cdecl;external DLLUtilName name 'CRYPTO_cleanup_all_ex_data';
  procedure _RandScreen; cdecl;external DLLUtilName name 'RAND_screen';
  function _BioNew(b: PBIO_METHOD): PBIO; cdecl;external DLLUtilName name 'BIO_new';
  procedure _BioFreeAll(b: PBIO); cdecl;external DLLUtilName name 'BIO_free_all';
  function _BioSMem: PBIO_METHOD; cdecl;external DLLUtilName name 'BIO_s_mem';
  function _BioCtrlPending(b: PBIO): integer; cdecl;external DLLUtilName name 'BIO_ctrl_pending';
  function _BioRead(b: PBIO; Buf: PByte; Len: integer): integer; cdecl;external DLLUtilName name 'BIO_read';
  function _BioWrite(b: PBIO; Buf: PByte; Len: integer): integer; cdecl;external DLLUtilName name 'BIO_write';
  function _d2iPKCS12bio(b:PBIO; Pkcs12: SslPtr): SslPtr; cdecl;external DLLUtilName name 'd2i_PKCS12_bio';
  function _PKCS12parse(p12: SslPtr; pass: PByte; var pkey, cert, ca: SslPtr): integer; cdecl;external DLLUtilName name 'PKCS12_parse';
  procedure _PKCS12free(p12: SslPtr); cdecl;external DLLUtilName name 'PKCS12_free';
  function _RsaGenerateKey(bits, e: integer; callback: PFunction; cb_arg: SslPtr): PRSA; cdecl;external DLLUtilName name 'RSA_generate_key';
  function _Asn1UtctimeNew: PASN1_UTCTIME; cdecl;external DLLUtilName name 'ASN1_UTCTIME_new';
  procedure _Asn1UtctimeFree(a: PASN1_UTCTIME); cdecl;external DLLUtilName name 'ASN1_UTCTIME_free';
  function _Asn1IntegerSet(a: PASN1_INTEGER; v: integer): integer; cdecl;external DLLUtilName name 'ASN1_INTEGER_set';
  function _Asn1IntegerGet(a: PASN1_INTEGER): integer; cdecl;external DLLUtilName name 'ASN1_INTEGER_get';
  function _i2dX509bio(b: PBIO; x: PX509): integer; cdecl;external DLLUtilName name 'i2d_X509_bio';
  function _d2iX509bio(b:PBIO;  x:PX509):   PX509;   cdecl; external DLLUtilName name 'd2i_X509_bio';
  function _PEMReadBioX509(b:PBIO;  {var x:PX509;}x:PSslPtr; callback:PFunction; cb_arg:SslPtr): PX509; cdecl; external DLLUtilName name 'PEM_read_bio_X509';
{$IFNDEF MSWINDOWS}
  procedure _SkX509PopFree(st: PSTACK; func: TSkPopFreeFunc); cdecl; external DLLUtilName name 'sk_X509_pop_free';
{$ENDIF}
  function _i2dPrivateKeyBio(b: PBIO; pkey: EVP_PKEY): integer; cdecl;external DLLUtilName name 'i2d_PrivateKey_bio';


  // 3DES functions
  procedure _DESsetoddparity(Key: des_cblock); cdecl;external DLLUtilName name 'DES_set_odd_parity';
  function _DESsetkeychecked (key: des_cblock; schedule: des_key_schedule): Integer; cdecl;external DLLUtilName name 'DES_set_key_checked';
  procedure _DESecbencrypt(Input: des_cblock; output: des_cblock; ks: des_key_schedule; enc: Integer); cdecl;external DLLUtilName name 'DES_ecb_encrypt';
  //thread lock functions
  function _CRYPTOnumlocks: integer; cdecl;external DLLUtilName name 'CRYPTO_num_locks';
  procedure _CRYPTOSetLockingCallback(cb: Sslptr); cdecl; external DLLUtilName name 'CRYPTO_set_locking_callback';
{$ENDIF}
{$ENDIF}


var
  SSLCS: TCriticalSection;
  SSLloaded: boolean = false;
{$IFNDEF CIL}
  Locks: Array of TCriticalSection;
{$ENDIF}

{$IFNDEF CIL}
// libssl.dll
function SslGetError(s: PSSL; ret_code: Integer):Integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslGetError){$ENDIF} then
    Result := _SslGetError(s, ret_code)
  else
    Result := SSL_ERROR_SSL;
end;

function SslLibraryInit:Integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslLibraryInit){$ENDIF} then
    Result := _SslLibraryInit
  else
    Result := 1;
end;

procedure SslLoadErrorStrings;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslLoadErrorStrings){$ENDIF} then
    _SslLoadErrorStrings;
end;

function SslCtxSetCipherList(arg0: PSSL_CTX; str: PByte):Integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslCtxSetCipherList){$ENDIF} then
    Result := _SslCtxSetCipherList(arg0, str)
  else
    Result := 0;
end;

function SslCtxNew(meth: PSSL_METHOD):PSSL_CTX;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslCtxNew){$ENDIF} then
    Result := _SslCtxNew(meth)
  else
    Result := nil;
end;

procedure SslCtxFree(arg0: PSSL_CTX);
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslCtxFree){$ENDIF} then
    _SslCtxFree(arg0);
end;

function SslSetFd(s: PSSL; fd: Integer):Integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslSetFd){$ENDIF} then
    Result := _SslSetFd(s, fd)
  else
    Result := 0;
end;

function SslMethodV2:PSSL_METHOD;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslMethodV2){$ENDIF} then
    Result := _SslMethodV2
  else
    Result := nil;
end;

function SslMethodV3:PSSL_METHOD;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslMethodV3){$ENDIF} then
    Result := _SslMethodV3
  else
    Result := nil;
end;

function SslMethodTLSV1:PSSL_METHOD;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslMethodTLSV1){$ENDIF} then
    Result := _SslMethodTLSV1
  else
    Result := nil;
end;

function SslMethodV23:PSSL_METHOD;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslMethodV23){$ENDIF} then
    Result := _SslMethodV23
  else
    Result := nil;
end;

function SslCtxUsePrivateKey(ctx: PSSL_CTX; pkey: SslPtr):Integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslCtxUsePrivateKey){$ENDIF} then
    Result := _SslCtxUsePrivateKey(ctx, pkey)
  else
    Result := 0;
end;

function SslCtxUsePrivateKeyASN1(pk: integer; ctx: PSSL_CTX; d: TSynaBytes; len: integer):Integer;
var buf: PByte;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslCtxUsePrivateKeyASN1){$ENDIF} then
  begin
    {$IFDEF UNICODE}
      buf :=  TSynaBytes(d).Data;
    {$ELSE}
      buf := PByte(d);
    {$ENDIF}
    Result := _SslCtxUsePrivateKeyASN1(pk, ctx, Sslptr(buf), len)
  end
  else
    Result := 0;
end;

//function SslCtxUsePrivateKeyFile(ctx: PSSL_CTX; const _file: PChar; _type: Integer):Integer;
function SslCtxUsePrivateKeyFile(ctx: PSSL_CTX; const _file: TSynaBytes; _type: Integer):Integer;
var buf: PByte;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslCtxUsePrivateKeyFile){$ENDIF} then
  begin
  {$IFDEF UNICODE}
      buf :=  TSynaBytes(_file).Data;
    {$ELSE}
      buf := Pointer(_file);
    {$ENDIF}
    Result := _SslCtxUsePrivateKeyFile(ctx, buf, _type)
  end
  else
    Result := 0;
end;

function SslCtxUseCertificate(ctx: PSSL_CTX; x: SslPtr):Integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslCtxUseCertificate){$ENDIF} then
    Result := _SslCtxUseCertificate(ctx, x)
  else
    Result := 0;
end;

function SslCtxUseCertificateASN1(ctx: PSSL_CTX; len: integer; d: TSynaBytes):Integer;
var buf: PByte;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslCtxUseCertificateASN1){$ENDIF} then
  begin
    {$IFDEF UNICODE}
      buf :=  TSynaBytes(d).Data;
    {$ELSE}
      buf := PByte(d);
    {$ENDIF}
    Result := _SslCtxUseCertificateASN1(ctx, len, SslPtr(buf))
  end
  else
    Result := 0;
end;

function SslCtxUseCertificateFile(ctx: PSSL_CTX; const _file: TSynaBytes; _type: Integer):Integer;
var buf: PByte;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslCtxUseCertificateFile){$ENDIF} then
  begin
   {$IFDEF UNICODE}
      buf :=  TSynaBytes(_file).Data;
    {$ELSE}
      buf := PByte(_file);
    {$ENDIF}
    Result := _SslCtxUseCertificateFile(ctx, buf, _type)
  end
   else
    Result := 0;
end;

//function SslCtxUseCertificateChainFile(ctx: PSSL_CTX; const _file: PChar):Integer;
function SslCtxUseCertificateChainFile(ctx: PSSL_CTX; const _file: TSynaBytes):Integer;
var buf: PByte;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslCtxUseCertificateChainFile){$ENDIF} then
  begin
    {$IFDEF UNICODE}
      buf :=  TSynaBytes(_file).Data;
    {$ELSE}
      buf := Pointer(_file);
    {$ENDIF}
    Result := _SslCtxUseCertificateChainFile(ctx, buf)
  end
  else
    Result := 0;
end;

function SslCtxCheckPrivateKeyFile(ctx: PSSL_CTX):Integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslCtxCheckPrivateKeyFile){$ENDIF} then
    Result := _SslCtxCheckPrivateKeyFile(ctx)
  else
    Result := 0;
end;

procedure SslCtxSetDefaultPasswdCb(ctx: PSSL_CTX; cb: PPasswdCb);
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslCtxSetDefaultPasswdCb){$ENDIF} then
    _SslCtxSetDefaultPasswdCb(ctx, cb);
end;

procedure SslCtxSetDefaultPasswdCbUserdata(ctx: PSSL_CTX; u: SslPtr);
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslCtxSetDefaultPasswdCbUserdata){$ENDIF} then
    _SslCtxSetDefaultPasswdCbUserdata(ctx, u);
end;

//function SslCtxLoadVerifyLocations(ctx: PSSL_CTX; const CAfile: PChar; const CApath: PChar):Integer;
function SslCtxLoadVerifyLocations(ctx: PSSL_CTX; const CAfile: TSynaBytes; const CApath: TSynaBytes):Integer;
var buf,path: PByte;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslCtxLoadVerifyLocations){$ENDIF} then
  begin
   {$IFDEF UNICODE}
      buf :=  TSynaBytes(CAfile).Data;
      path := TSynaBytes(CApath).Data;
    {$ELSE}
      buf := PByte(CAfile);
      path := PByte(CApath);
    {$ENDIF}
    Result := _SslCtxLoadVerifyLocations(ctx, SslPtr(buf), SslPtr(path))
  end
  else
    Result := 0;
end;

function SslCtxCtrl(ctx: PSSL_CTX; cmd: integer; larg: integer; parg: SslPtr): integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslCtxCtrl){$ENDIF} then
    Result := _SslCtxCtrl(ctx, cmd, larg, parg)
  else
    Result := 0;
end;

function SslNew(ctx: PSSL_CTX):PSSL;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslNew){$ENDIF} then
    Result := _SslNew(ctx)
  else
    Result := nil;
end;

procedure SslFree(ssl: PSSL);
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslFree){$ENDIF} then
    _SslFree(ssl);
end;

function SslAccept(ssl: PSSL):Integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslAccept) {$ENDIF}then
    Result := _SslAccept(ssl)
  else
    Result := -1;
end;

function SslConnect(ssl: PSSL):Integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslConnect) {$ENDIF}then
    Result := _SslConnect(ssl)
  else
    Result := -1;
end;

function SslShutdown(ssl: PSSL):Integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslShutdown){$ENDIF} then
    Result := _SslShutdown(ssl)
  else
    Result := -1;
end;

//function SslRead(ssl: PSSL; buf: PChar; num: Integer):Integer;
function SslRead(ssl: PSSL; buf: SslPtr; num: Integer):Integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslRead) {$ENDIF}then
    Result := _SslRead(ssl, PByte(buf), num)
  else
    Result := -1;
end;

//function SslPeek(ssl: PSSL; buf: PChar; num: Integer):Integer;
function SslPeek(ssl: PSSL; buf: SslPtr; num: Integer):Integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslPeek){$ENDIF} then
    Result := _SslPeek(ssl, PByte(buf), num)
  else
    Result := -1;
end;

//function SslWrite(ssl: PSSL; const buf: PChar; num: Integer):Integer;
function SslWrite(ssl: PSSL; buf: SslPtr; num: Integer):Integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslWrite){$ENDIF} then
    Result := _SslWrite(ssl, PByte(buf), num)
  else
    Result := -1;
end;

function SslPending(ssl: PSSL):Integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslPending){$ENDIF} then
    Result := _SslPending(ssl)
  else
    Result := 0;
end;

//function SslGetVersion(ssl: PSSL):PChar;
function SslGetVersion(ssl: PSSL):string;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslGetVersion){$ENDIF} then
    Result := StringOf(_SslGetVersion(ssl))
  else
    Result := '';
end;

function SslGetPeerCertificate(ssl: PSSL):PX509;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslGetPeerCertificate){$ENDIF} then
    Result := _SslGetPeerCertificate(ssl)
  else
    Result := nil;
end;

//procedure SslCtxSetVerify(ctx: PSSL_CTX; mode: Integer; arg2: SslPtr);
procedure SslCtxSetVerify(ctx: PSSL_CTX; mode: Integer; arg2: PFunction);
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SslCtxSetVerify){$ENDIF} then
    _SslCtxSetVerify(ctx, mode, @arg2);
end;

function SSLGetCurrentCipher(s: PSSL):SslPtr;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SSLGetCurrentCipher){$ENDIF} then
{$IFDEF CIL}
{$ELSE}
    Result := _SSLGetCurrentCipher(s)
{$ENDIF}
  else
    Result := nil;
end;

//function SSLCipherGetName(c: SslPtr):PChar;
function SSLCipherGetName(c: SslPtr):String;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SSLCipherGetName){$ENDIF} then
    Result := StringOf(_SSLCipherGetName(c))
  else
    Result := '';
end;

//function SSLCipherGetBits(c: SslPtr; alg_bits: PInteger):Integer;
function SSLCipherGetBits(c: SslPtr; var alg_bits: Integer):Integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SSLCipherGetBits){$ENDIF} then
    Result := _SSLCipherGetBits(c, @alg_bits)
  else
    Result := 0;
end;

function SSLGetVerifyResult(ssl: PSSL):Integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SSLGetVerifyResult){$ENDIF} then
    Result := _SSLGetVerifyResult(ssl)
  else
    Result := X509_V_ERR_APPLICATION_VERIFICATION;
end;


function SSLCtrl(ssl: PSSL; cmd: integer; larg: integer; parg: SslPtr):Integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SSLCtrl){$ENDIF} then
    Result := _SSLCtrl(ssl, cmd, larg, parg)
  else
    Result := X509_V_ERR_APPLICATION_VERIFICATION;
end;

// libeay.dll
function X509New: PX509;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_X509New){$ENDIF} then
    Result := _X509New
  else
    Result := nil;
end;

procedure X509Free(x: PX509);
begin
  if InitSSLInterface and Assigned(_X509Free) then
    _X509Free(x);
end;

function X509NameOneline(a: PX509_NAME; buf: PByte; size: Integer): String;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_X509NameOneline){$ENDIF} then
    Result := StringOf(_X509NameOneline(a, buf,size))
  else
    Result := '';
end;

function X509GetSubjectName(a: PX509):PX509_NAME;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_X509GetSubjectName){$ENDIF} then
    Result := _X509GetSubjectName(a)
  else
    Result := nil;
end;

function X509GetIssuerName(a: PX509):PX509_NAME;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_X509GetIssuerName){$ENDIF} then
    Result := _X509GetIssuerName(a)
  else
    Result := nil;
end;

function X509NameHash(x: PX509_NAME):Cardinal;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_X509NameHash){$ENDIF} then
    Result := _X509NameHash(x)
  else
    Result := 0;
end;

//function SslX509Digest(data: PX509; _type: PEVP_MD; md: PChar; len: PInteger):Integer;
function X509Digest(data: PX509; _type: PEVP_MD; md: TSynaBytes; var len: Integer):Integer;
var buf: PByte;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_X509Digest){$ENDIF} then
  begin
  {$IFDEF UNICODE}
      buf :=  TSynaBytes(md).Data;
    {$ELSE}
      buf := PByte(md);
    {$ENDIF}
    Result := _X509Digest(data, _type, buf, @len)
  end
  else
    Result := 0;
end;

function EvpPkeyNew: EVP_PKEY;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_EvpPkeyNew){$ENDIF} then
    Result := _EvpPkeyNew
  else
    Result := nil;
end;

procedure EvpPkeyFree(pk: EVP_PKEY);
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_EvpPkeyFree){$ENDIF} then
    _EvpPkeyFree(pk);
end;

function SSLeayversion(t: integer): string;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SSLeayversion){$ENDIF} then
    Result := StringOf(_SSLeayversion(t))
  else
    Result := '';
end;

procedure ErrErrorString(e: integer; var buf: TSynaBytes; len: integer);
var ptr: PByte;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_ErrErrorString){$ENDIF} then
  begin
    {$IFDEF UNICODE}
      ptr :=  TSynaBytes(buf).Data;
    {$ELSE}
      ptr := PByte(buf);
    {$ENDIF}
    _ErrErrorString(e, ptr, len);
  end;
end;

function ErrGetError: integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_ErrGetError){$ENDIF} then
    Result := _ErrGetError
  else
    Result := SSL_ERROR_SSL;
end;

procedure ErrClearError;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_ErrClearError){$ENDIF} then
    _ErrClearError;
end;

procedure ErrFreeStrings;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_ErrFreeStrings){$ENDIF} then
    _ErrFreeStrings;
end;

procedure ErrRemoveState(pid: integer);
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_ErrRemoveState){$ENDIF} then
    _ErrRemoveState(pid);
end;

procedure OPENSSLaddallalgorithms;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_OPENSSLaddallalgorithms){$ENDIF} then
    _OPENSSLaddallalgorithms;
end;

procedure EVPcleanup;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_EVPcleanup){$ENDIF} then
    _EVPcleanup;
end;

procedure CRYPTOcleanupAllExData;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_CRYPTOcleanupAllExData){$ENDIF} then
    _CRYPTOcleanupAllExData;
end;

procedure RandScreen;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_RandScreen){$ENDIF} then
    _RandScreen;
end;

function BioNew(b: PBIO_METHOD): PBIO;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_BioNew){$ENDIF} then
    Result := _BioNew(b)
  else
    Result := nil;
end;

procedure BioFreeAll(b: PBIO);
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_BioFreeAll){$ENDIF} then
    _BioFreeAll(b);
end;

function BioSMem: PBIO_METHOD;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_BioSMem){$ENDIF} then
    Result := _BioSMem
  else
    Result := nil;
end;

function BioCtrlPending(b: PBIO): integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_BioCtrlPending){$ENDIF} then
    Result := _BioCtrlPending(b)
  else
    Result := 0;
end;

//function BioRead(b: PBIO; Buf: PChar; Len: integer): integer;
function BioRead(b: PBIO; Buf: PByte; Len: integer): integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_BioRead){$ENDIF} then
    Result := _BioRead(b, buf, Len)
  else
    Result := -2;
end;

//function BioWrite(b: PBIO; Buf: PChar; Len: integer): integer;
function BioWrite(b: PBIO; Buf: PByte; Len: integer): integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_BioWrite){$ENDIF} then
    Result := _BioWrite(b, Buf, Len)
  else
    Result := -2;
end;

function X509print(b: PBIO; a: PX509): integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_X509print){$ENDIF} then
    Result := _X509print(b, a)
  else
    Result := 0;
end;

function d2iPKCS12bio(b:PBIO; Pkcs12: SslPtr): SslPtr;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_d2iPKCS12bio){$ENDIF} then
    Result := _d2iPKCS12bio(b, Pkcs12)
  else
    Result := nil;
end;

function PKCS12parse(p12: SslPtr; pass: TSynaBytes; var pkey, cert, ca: SslPtr): integer;
var buf: PByte;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_PKCS12parse){$ENDIF} then
  begin
     {$IFDEF UNICODE}
      buf :=  TSynaBytes(pass).Data;
    {$ELSE}
      buf := Pointer(pass);
    {$ENDIF}
    Result := _PKCS12parse(p12, SslPtr(buf), pkey, cert, ca)
  end
  else
    Result := 0;
end;

procedure PKCS12free(p12: SslPtr);
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_PKCS12free){$ENDIF} then
    _PKCS12free(p12);
end;

function RsaGenerateKey(bits, e: integer; callback: PFunction; cb_arg: SslPtr): PRSA;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_RsaGenerateKey){$ENDIF} then
    Result := _RsaGenerateKey(bits, e, callback, cb_arg)
  else
    Result := nil;
end;

function EvpPkeyAssign(pkey: EVP_PKEY; _type: integer; key: Prsa): integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_EvpPkeyAssign){$ENDIF} then
    Result := _EvpPkeyAssign(pkey, _type, key)
  else
    Result := 0;
end;

function X509SetVersion(x: PX509; version: integer): integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_X509SetVersion){$ENDIF} then
    Result := _X509SetVersion(x, version)
  else
    Result := 0;
end;

function X509SetPubkey(x: PX509; pkey: EVP_PKEY): integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_X509SetPubkey){$ENDIF} then
    Result := _X509SetPubkey(x, pkey)
  else
    Result := 0;
end;

function X509SetIssuerName(x: PX509; name: PX509_NAME): integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_X509SetIssuerName){$ENDIF} then
    Result := _X509SetIssuerName(x, name)
  else
    Result := 0;
end;

function X509NameAddEntryByTxt(name: PX509_NAME; field: TSynaBytes; _type: integer;
  bytes: TSynaBytes; len, loc, _set: integer): integer;
var buf: PByte;
  strb: PByte;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_X509NameAddEntryByTxt){$ENDIF} then
  begin
   {$IFDEF UNICODE}
      buf :=  TSynaBytes(field).Data;
      strb := TSynaBytes(bytes).Data;
    {$ELSE}
      buf := Pointer(field);
      strb := Pointer(bytes);
    {$ENDIF}
    Result := _X509NameAddEntryByTxt(name, buf, _type, strb, len, loc, _set)
  end
  else
    Result := 0;
end;

function X509Sign(x: PX509; pkey: EVP_PKEY; const md: PEVP_MD): integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_X509Sign){$ENDIF} then
    Result := _X509Sign(x, pkey, md)
  else
    Result := 0;
end;

function Asn1UtctimeNew: PASN1_UTCTIME;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_Asn1UtctimeNew){$ENDIF} then
    Result := _Asn1UtctimeNew
  else
    Result := nil;
end;

procedure Asn1UtctimeFree(a: PASN1_UTCTIME);
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_Asn1UtctimeFree){$ENDIF} then
    _Asn1UtctimeFree(a);
end;

function X509GmtimeAdj(s: PASN1_UTCTIME; adj: integer): PASN1_UTCTIME;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_X509GmtimeAdj){$ENDIF} then
    Result := _X509GmtimeAdj(s, adj)
  else
    Result := nil;
end;

function X509SetNotBefore(x: PX509; tm: PASN1_UTCTIME): integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_X509SetNotBefore){$ENDIF} then
    Result := _X509SetNotBefore(x, tm)
  else
    Result := 0;
end;

function X509SetNotAfter(x: PX509; tm: PASN1_UTCTIME): integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_X509SetNotAfter){$ENDIF} then
    Result := _X509SetNotAfter(x, tm)
  else
    Result := 0;
end;

function i2dX509bio(b: PBIO; x: PX509): integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_i2dX509bio){$ENDIF} then
    Result := _i2dX509bio(b, x)
  else
    Result := 0;
end;

function d2iX509bio(b: PBIO; x: PX509): PX509; {pf}
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_d2iX509bio){$ENDIF} then
    Result := _d2iX509bio(x,b)
  else
    Result := nil;
end;

function PEMReadBioX509(b:PBIO; {var x:PX509;}x:PSslPtr; callback:PFunction; cb_arg: SslPtr):  PX509;    {pf}
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_PEMReadBioX509){$ENDIF} then
    Result := _PEMReadBioX509(b,x,callback,cb_arg)
  else
    Result := nil;
end;

procedure SkX509PopFree(st: PSTACK; func:TSkPopFreeFunc); {pf}
begin
{$IFNDEF MSWINDOWS}
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_SkX509PopFree){$ENDIF} then
    _SkX509PopFree(st,func);
{$ENDIF}
end;

function i2dPrivateKeyBio(b: PBIO; pkey: EVP_PKEY): integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_i2dPrivateKeyBio){$ENDIF} then
    Result := _i2dPrivateKeyBio(b, pkey)
  else
    Result := 0;
end;

function EvpGetDigestByName(Name: TSynaBytes): PEVP_MD;
var buf: PByte;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_EvpGetDigestByName){$ENDIF} then
  begin
         {$IFDEF UNICODE}
      buf :=  TSynaBytes(name).Data;
    {$ELSE}
      buf := PByte(name);
    {$ENDIF}
    Result := _EvpGetDigestByName(buf)
  end
  else
    Result := nil;
end;

function Asn1IntegerSet(a: PASN1_INTEGER; v: integer): integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_Asn1IntegerSet){$ENDIF} then
    Result := _Asn1IntegerSet(a, v)
  else
    Result := 0;
end;

function Asn1IntegerGet(a: PASN1_INTEGER): integer; {pf}
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_Asn1IntegerGet){$ENDIF} then
    Result := _Asn1IntegerGet(a)
  else
    Result := 0;
end;

function X509GetSerialNumber(x: PX509): PASN1_INTEGER;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_X509GetSerialNumber){$ENDIF} then
    Result := _X509GetSerialNumber(x)
  else
    Result := nil;
end;

// 3DES functions
procedure DESsetoddparity(Key: des_cblock);
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_DESsetoddparity){$ENDIF} then
    _DESsetoddparity(Key);
end;

function DESsetkeychecked(key: des_cblock; schedule: des_key_schedule): Integer;
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_DESsetkeychecked){$ENDIF} then
    Result := _DESsetkeychecked(key, schedule)
  else
    Result := -1;
end;

procedure DESecbencrypt(Input: des_cblock; output: des_cblock; ks: des_key_schedule; enc: Integer);
begin
  if InitSSLInterface {$IFNDEF STATIC}and Assigned(_DESecbencrypt){$ENDIF} then
    _DESecbencrypt(Input, output, ks, enc);
end;

procedure locking_callback(mode, ltype: integer; lfile: PChar; line: integer); cdecl;
begin
  if ltype>High(Locks) then exit; //Should never happen?
  
  if (mode and 1) > 0 then
    TCriticalSection(Locks[ltype]).Enter
  else
    TCriticalSection(Locks[ltype]).Leave;
end;

procedure InitLocks;
var
  n: integer;
begin
  Setlength(Locks, _CRYPTOnumlocks);
  for n := 0 to high(Locks) do
    Locks[n] := TCriticalSection.Create;
  _CRYPTOsetlockingcallback(@locking_callback);
end;

procedure FreeLocks;
var
  n: integer;
begin
  _CRYPTOsetlockingcallback(nil);
  for n := 0 to high(Locks) do
    Locks[n].Free;
  Setlength(Locks, 0);
end;

{$ENDIF}

{$IFNDEF STATIC}
function LoadLib(const Value: String): HModule;
begin
{$IFDEF CIL}
  Result := LoadLibrary(Value);
{$ELSE}
  Result := LoadLibrary(PChar(Value));
{$ENDIF}
end;

function GetProcAddr(module: HModule; const ProcName: string): SslPtr;
begin
{$IFDEF CIL}
  Result := GetProcAddress(module, ProcName);
{$ELSE}
  Result := GetProcAddress(module, PChar(ProcName));
{$ENDIF}
end;
{$ENDIF}

function InitSSLInterface: Boolean;
var
  s: string;
  x: integer;
begin
  {pf}
  if SSLLoaded then
    begin
      Result := TRUE;
      exit;
    end;
  {/pf}  
  SSLCS.Enter;
  try
    if not IsSSLloaded then
    begin
{$IFDEF CIL}
      SSLLibHandle := 1;
      SSLUtilHandle := 1;
{$ELSE}
{$IFDEF STATIC}
      SSLLibHandle := 1;
      SSLUtilHandle := 1;
{$ELSE}
      SSLUtilHandle := LoadLib(DLLUtilName);
      SSLLibHandle := LoadLib(DLLSSLName);
  {$IFDEF MSWINDOWS}
      if (SSLLibHandle = 0) then
        SSLLibHandle := LoadLib(DLLSSLName2);
  {$ENDIF}
{$ENDIF}

{$ENDIF}
      if (SSLLibHandle <> 0) and (SSLUtilHandle <> 0) then
      begin
{$IFNDEF CIL}
 {$IFNDEF STATIC}
        _SslGetError := GetProcAddr(SSLLibHandle, 'SSL_get_error');
        _SslLibraryInit := GetProcAddr(SSLLibHandle, 'SSL_library_init');
        _SslLoadErrorStrings := GetProcAddr(SSLLibHandle, 'SSL_load_error_strings');
        _SslCtxSetCipherList := GetProcAddr(SSLLibHandle, 'SSL_CTX_set_cipher_list');
        _SslCtxNew := GetProcAddr(SSLLibHandle, 'SSL_CTX_new');
        _SslCtxFree := GetProcAddr(SSLLibHandle, 'SSL_CTX_free');
        _SslSetFd := GetProcAddr(SSLLibHandle, 'SSL_set_fd');
        _SslMethodV2 := GetProcAddr(SSLLibHandle, 'SSLv2_method');
        _SslMethodV3 := GetProcAddr(SSLLibHandle, 'SSLv3_method');
        _SslMethodTLSV1 := GetProcAddr(SSLLibHandle, 'TLSv1_method');
        _SslMethodV23 := GetProcAddr(SSLLibHandle, 'SSLv23_method');
        _SslCtxUsePrivateKey := GetProcAddr(SSLLibHandle, 'SSL_CTX_use_PrivateKey');
        _SslCtxUsePrivateKeyASN1 := GetProcAddr(SSLLibHandle, 'SSL_CTX_use_PrivateKey_ASN1');
        //use SSL_CTX_use_RSAPrivateKey_file instead SSL_CTX_use_PrivateKey_file,
        //because SSL_CTX_use_PrivateKey_file not support DER format. :-O
        _SslCtxUsePrivateKeyFile := GetProcAddr(SSLLibHandle, 'SSL_CTX_use_RSAPrivateKey_file');
        _SslCtxUseCertificate := GetProcAddr(SSLLibHandle, 'SSL_CTX_use_certificate');
        _SslCtxUseCertificateASN1 := GetProcAddr(SSLLibHandle, 'SSL_CTX_use_certificate_ASN1');
        _SslCtxUseCertificateFile := GetProcAddr(SSLLibHandle, 'SSL_CTX_use_certificate_file');
        _SslCtxUseCertificateChainFile := GetProcAddr(SSLLibHandle, 'SSL_CTX_use_certificate_chain_file');
        _SslCtxCheckPrivateKeyFile := GetProcAddr(SSLLibHandle, 'SSL_CTX_check_private_key');
        _SslCtxSetDefaultPasswdCb := GetProcAddr(SSLLibHandle, 'SSL_CTX_set_default_passwd_cb');
        _SslCtxSetDefaultPasswdCbUserdata := GetProcAddr(SSLLibHandle, 'SSL_CTX_set_default_passwd_cb_userdata');
        _SslCtxLoadVerifyLocations := GetProcAddr(SSLLibHandle, 'SSL_CTX_load_verify_locations');
        _SslCtxCtrl := GetProcAddr(SSLLibHandle, 'SSL_CTX_ctrl');
        _SslNew := GetProcAddr(SSLLibHandle, 'SSL_new');
        _SslFree := GetProcAddr(SSLLibHandle, 'SSL_free');
        _SslAccept := GetProcAddr(SSLLibHandle, 'SSL_accept');
        _SslConnect := GetProcAddr(SSLLibHandle, 'SSL_connect');
        _SslShutdown := GetProcAddr(SSLLibHandle, 'SSL_shutdown');
        _SslRead := GetProcAddr(SSLLibHandle, 'SSL_read');
        _SslPeek := GetProcAddr(SSLLibHandle, 'SSL_peek');
        _SslWrite := GetProcAddr(SSLLibHandle, 'SSL_write');
        _SslPending := GetProcAddr(SSLLibHandle, 'SSL_pending');
        _SslGetPeerCertificate := GetProcAddr(SSLLibHandle, 'SSL_get_peer_certificate');
        _SslGetVersion := GetProcAddr(SSLLibHandle, 'SSL_get_version');
        _SslCtxSetVerify := GetProcAddr(SSLLibHandle, 'SSL_CTX_set_verify');
        _SslGetCurrentCipher := GetProcAddr(SSLLibHandle, 'SSL_get_current_cipher');
        _SslCipherGetName := GetProcAddr(SSLLibHandle, 'SSL_CIPHER_get_name');
        _SslCipherGetBits := GetProcAddr(SSLLibHandle, 'SSL_CIPHER_get_bits');
        _SslGetVerifyResult := GetProcAddr(SSLLibHandle, 'SSL_get_verify_result');
        _SslCtrl := GetProcAddr(SSLLibHandle, 'SSL_ctrl');

        _X509New := GetProcAddr(SSLUtilHandle, 'X509_new');
        _X509Free := GetProcAddr(SSLUtilHandle, 'X509_free');
        _X509NameOneline := GetProcAddr(SSLUtilHandle, 'X509_NAME_oneline');
        _X509GetSubjectName := GetProcAddr(SSLUtilHandle, 'X509_get_subject_name');
        _X509GetIssuerName := GetProcAddr(SSLUtilHandle, 'X509_get_issuer_name');
        _X509NameHash := GetProcAddr(SSLUtilHandle, 'X509_NAME_hash');
        _X509Digest := GetProcAddr(SSLUtilHandle, 'X509_digest');
        _X509print := GetProcAddr(SSLUtilHandle, 'X509_print');
        _X509SetVersion := GetProcAddr(SSLUtilHandle, 'X509_set_version');
        _X509SetPubkey := GetProcAddr(SSLUtilHandle, 'X509_set_pubkey');
        _X509SetIssuerName := GetProcAddr(SSLUtilHandle, 'X509_set_issuer_name');
        _X509NameAddEntryByTxt := GetProcAddr(SSLUtilHandle, 'X509_NAME_add_entry_by_txt');
        _X509Sign := GetProcAddr(SSLUtilHandle, 'X509_sign');
        _X509GmtimeAdj := GetProcAddr(SSLUtilHandle, 'X509_gmtime_adj');
        _X509SetNotBefore := GetProcAddr(SSLUtilHandle, 'X509_set_notBefore');
        _X509SetNotAfter := GetProcAddr(SSLUtilHandle, 'X509_set_notAfter');
        _X509GetSerialNumber := GetProcAddr(SSLUtilHandle, 'X509_get_serialNumber');
        _EvpPkeyNew := GetProcAddr(SSLUtilHandle, 'EVP_PKEY_new');
        _EvpPkeyFree := GetProcAddr(SSLUtilHandle, 'EVP_PKEY_free');
        _EvpPkeyAssign := GetProcAddr(SSLUtilHandle, 'EVP_PKEY_assign');
        _EVPCleanup := GetProcAddr(SSLUtilHandle, 'EVP_cleanup');
        _EvpGetDigestByName := GetProcAddr(SSLUtilHandle, 'EVP_get_digestbyname');
        _SSLeayversion := GetProcAddr(SSLUtilHandle, 'SSLeay_version');
        _ErrErrorString := GetProcAddr(SSLUtilHandle, 'ERR_error_string_n');
        _ErrGetError := GetProcAddr(SSLUtilHandle, 'ERR_get_error');
        _ErrClearError := GetProcAddr(SSLUtilHandle, 'ERR_clear_error');
        _ErrFreeStrings := GetProcAddr(SSLUtilHandle, 'ERR_free_strings');
        _ErrRemoveState := GetProcAddr(SSLUtilHandle, 'ERR_remove_state');
        _OPENSSLaddallalgorithms := GetProcAddr(SSLUtilHandle, 'OPENSSL_add_all_algorithms_noconf');
        _CRYPTOcleanupAllExData := GetProcAddr(SSLUtilHandle, 'CRYPTO_cleanup_all_ex_data');
        _RandScreen := GetProcAddr(SSLUtilHandle, 'RAND_screen');
        _BioNew := GetProcAddr(SSLUtilHandle, 'BIO_new');
        _BioFreeAll := GetProcAddr(SSLUtilHandle, 'BIO_free_all');
        _BioSMem := GetProcAddr(SSLUtilHandle, 'BIO_s_mem');
        _BioCtrlPending := GetProcAddr(SSLUtilHandle, 'BIO_ctrl_pending');
        _BioRead := GetProcAddr(SSLUtilHandle, 'BIO_read');
        _BioWrite := GetProcAddr(SSLUtilHandle, 'BIO_write');
        _d2iPKCS12bio := GetProcAddr(SSLUtilHandle, 'd2i_PKCS12_bio');
        _PKCS12parse := GetProcAddr(SSLUtilHandle, 'PKCS12_parse');
        _PKCS12free := GetProcAddr(SSLUtilHandle, 'PKCS12_free');
        _RsaGenerateKey := GetProcAddr(SSLUtilHandle, 'RSA_generate_key');
        _Asn1UtctimeNew := GetProcAddr(SSLUtilHandle, 'ASN1_UTCTIME_new');
        _Asn1UtctimeFree := GetProcAddr(SSLUtilHandle, 'ASN1_UTCTIME_free');
        _Asn1IntegerSet := GetProcAddr(SSLUtilHandle, 'ASN1_INTEGER_set');
        _Asn1IntegerGet := GetProcAddr(SSLUtilHandle, 'ASN1_INTEGER_get'); {pf}
        _i2dX509bio := GetProcAddr(SSLUtilHandle, 'i2d_X509_bio');
        _d2iX509bio := GetProcAddr(SSLUtilHandle, 'd2i_X509_bio'); {pf}
        _PEMReadBioX509 := GetProcAddr(SSLUtilHandle, 'PEM_read_bio_X509'); {pf}
        _SkX509PopFree := GetProcAddr(SSLUtilHandle, 'SK_X509_POP_FREE'); {pf}
        _i2dPrivateKeyBio := GetProcAddr(SSLUtilHandle, 'i2d_PrivateKey_bio');

        // 3DES functions
        _DESsetoddparity := GetProcAddr(SSLUtilHandle, 'DES_set_odd_parity');
        _DESsetkeychecked := GetProcAddr(SSLUtilHandle, 'DES_set_key_checked');
        _DESecbencrypt := GetProcAddr(SSLUtilHandle, 'DES_ecb_encrypt');
        //
        _CRYPTOnumlocks := GetProcAddr(SSLUtilHandle, 'CRYPTO_num_locks');
        _CRYPTOsetlockingcallback := GetProcAddr(SSLUtilHandle, 'CRYPTO_set_locking_callback');
 {$ENDIF}// STATIC
{$ENDIF}
{$IFDEF CIL}
        SslLibraryInit;
        SslLoadErrorStrings;
        OPENSSLaddallalgorithms;
        RandScreen;
{$ELSE}
        SetLength(s, 1024);
        x := GetModuleFilename(SSLLibHandle,PChar(s),Length(s));
        SetLength(s, x);
        SSLLibFile := s;
        SetLength(s, 1024);
        x := GetModuleFilename(SSLUtilHandle,PChar(s),Length(s));
        SetLength(s, x);
        SSLUtilFile := s;
        //init library
        {$IFNDEF STATIC}if assigned(_SslLibraryInit) then{$ENDIF}
          _SslLibraryInit;
        {$IFNDEF STATIC}if assigned(_SslLoadErrorStrings) then{$ENDIF}
          _SslLoadErrorStrings;
        {$IFNDEF STATIC}if assigned(_OPENSSLaddallalgorithms) then{$ENDIF}
          _OPENSSLaddallalgorithms;
        {$IFNDEF STATIC}if assigned(_RandScreen) then{$ENDIF}
          _RandScreen;
        {$IFNDEF STATIC}
        if assigned(_CRYPTOnumlocks) and assigned(_CRYPTOsetlockingcallback) then
        {$ENDIF}
          InitLocks;
{$ENDIF}
        SSLloaded := True;
{$IFDEF OS2}
        Result := InitEMXHandles;
{$ELSE OS2}
        Result := True;
{$ENDIF OS2}
      end
      else
      begin
        //load failed!
        if SSLLibHandle <> 0 then
        begin
{$IFNDEF CIL}
          FreeLibrary(SSLLibHandle);
{$ENDIF}
          SSLLibHandle := 0;
        end;
        if SSLUtilHandle <> 0 then
        begin
{$IFNDEF CIL}
          FreeLibrary(SSLUtilHandle);
{$ENDIF}
          SSLLibHandle := 0;
        end;
        Result := False;
      end;
    end
    else
      //loaded before...
      Result := true;
  finally
    SSLCS.Leave;
  end;
end;

function DestroySSLInterface: Boolean;
begin
  SSLCS.Enter;
  try
    if IsSSLLoaded then
    begin
      //deinit library
{$IFNDEF CIL}
      {$IFNDEF STATIC}
      if assigned(_CRYPTOnumlocks) and assigned(_CRYPTOsetlockingcallback) then
      {$ENDIF}
        FreeLocks;
{$ENDIF}
      EVPCleanup;
      CRYPTOcleanupAllExData;
      ErrRemoveState(0);
    end;
    SSLloaded := false;
    if SSLLibHandle <> 0 then
    begin
{$IFNDEF CIL}
      FreeLibrary(SSLLibHandle);
{$ENDIF}
      SSLLibHandle := 0;
    end;
    if SSLUtilHandle <> 0 then
    begin
{$IFNDEF CIL}
      FreeLibrary(SSLUtilHandle);
{$ENDIF}
      SSLLibHandle := 0;
    end;

{$IFNDEF CIL}
{$IFNDEF STATIC}
    _SslGetError := nil;
    _SslLibraryInit := nil;
    _SslLoadErrorStrings := nil;
    _SslCtxSetCipherList := nil;
    _SslCtxNew := nil;
    _SslCtxFree := nil;
    _SslSetFd := nil;
    _SslMethodV2 := nil;
    _SslMethodV3 := nil;
    _SslMethodTLSV1 := nil;
    _SslMethodV23 := nil;
    _SslCtxUsePrivateKey := nil;
    _SslCtxUsePrivateKeyASN1 := nil;
    _SslCtxUsePrivateKeyFile := nil;
    _SslCtxUseCertificate := nil;
    _SslCtxUseCertificateASN1 := nil;
    _SslCtxUseCertificateFile := nil;
    _SslCtxUseCertificateChainFile := nil;
    _SslCtxCheckPrivateKeyFile := nil;
    _SslCtxSetDefaultPasswdCb := nil;
    _SslCtxSetDefaultPasswdCbUserdata := nil;
    _SslCtxLoadVerifyLocations := nil;
    _SslCtxCtrl := nil;
    _SslNew := nil;
    _SslFree := nil;
    _SslAccept := nil;
    _SslConnect := nil;
    _SslShutdown := nil;
    _SslRead := nil;
    _SslPeek := nil;
    _SslWrite := nil;
    _SslPending := nil;
    _SslGetPeerCertificate := nil;
    _SslGetVersion := nil;
    _SslCtxSetVerify := nil;
    _SslGetCurrentCipher := nil;
    _SslCipherGetName := nil;
    _SslCipherGetBits := nil;
    _SslGetVerifyResult := nil;
    _SslCtrl := nil;

    _X509New := nil;
    _X509Free := nil;
    _X509NameOneline := nil;
    _X509GetSubjectName := nil;
    _X509GetIssuerName := nil;
    _X509NameHash := nil;
    _X509Digest := nil;
    _X509print := nil;
    _X509SetVersion := nil;
    _X509SetPubkey := nil;
    _X509SetIssuerName := nil;
    _X509NameAddEntryByTxt := nil;
    _X509Sign := nil;
    _X509GmtimeAdj := nil;
    _X509SetNotBefore := nil;
    _X509SetNotAfter := nil;
    _X509GetSerialNumber := nil;
    _EvpPkeyNew := nil;
    _EvpPkeyFree := nil;
    _EvpPkeyAssign := nil;
    _EVPCleanup := nil;
    _EvpGetDigestByName := nil;
    _SSLeayversion := nil;
    _ErrErrorString := nil;
    _ErrGetError := nil;
    _ErrClearError := nil;
    _ErrFreeStrings := nil;
    _ErrRemoveState := nil;
    _OPENSSLaddallalgorithms := nil;
    _CRYPTOcleanupAllExData := nil;
    _RandScreen := nil;
    _BioNew := nil;
    _BioFreeAll := nil;
    _BioSMem := nil;
    _BioCtrlPending := nil;
    _BioRead := nil;
    _BioWrite := nil;
    _d2iPKCS12bio := nil;
    _PKCS12parse := nil;
    _PKCS12free := nil;
    _RsaGenerateKey := nil;
    _Asn1UtctimeNew := nil;
    _Asn1UtctimeFree := nil;
    _Asn1IntegerSet := nil;
    _Asn1IntegerGet := nil; {pf}
    _SkX509PopFree := nil; {pf}
    _i2dX509bio := nil;
    _i2dPrivateKeyBio := nil;

    // 3DES functions
    _DESsetoddparity := nil;
    _DESsetkeychecked := nil;
    _DESecbencrypt := nil;
    //
    _CRYPTOnumlocks := nil;
    _CRYPTOsetlockingcallback := nil;
{$ENDIF}
{$ENDIF}
  finally
    SSLCS.Leave;
  end;
  Result := True;
end;

function IsSSLloaded: Boolean;
begin
  Result := SSLLoaded;
end;

initialization
begin
  SSLCS:= TCriticalSection.Create;
end;

finalization
begin
{$IFNDEF CIL}
  DestroySSLInterface;
{$ENDIF}
  SSLCS.Free;
end;

end.
