/*
** ----------------------------------------------------------------------
** ocsp.c: Iplanet ocsp client
** 
** Feb/2006
**		
** ----------------------------------------------------------------------
*/

#include "stdio.h"
#include "time.h"
#include "string.h"
#include "sys/types.h"
#include "unistd.h"
#include "dirent.h"


#include "openssl/bio.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"
#include "openssl/ocsp.h"
#include "openssl/ssl.h"
#include "openssl/err.h"


#ifdef _BUILD_NSAPI_
/*
** ------------------------------------------------------------
** BEGIN MULTIPLATAFORM DEFINES
** ------------------------------------------------------------
*/
#ifdef XP_WIN32
#define NSAPI_PUBLIC __declspec(dllexport)
#else /* !XP_WIN32 */
#define NSAPI_PUBLIC
#endif /* !XP_WIN32 */
/*
** ------------------------------------------------------------
** END MULTIPLATAFORM DEFINES
** ------------------------------------------------------------
*/



/*
** ------------------------------------------------------------
** BEGIN NSAPI INCLUDES
** ------------------------------------------------------------
*/
#include "nsapi.h"
#include "base/util.h"       
#include "frame/protocol.h"  
#include "base/file.h"       
#include "base/buffer.h"     
#include "frame/log.h"
/*
** ------------------------------------------------------------
** END NSAPI INCLUDES
** ------------------------------------------------------------
*/
#endif

/*
** ------------------------------------------------------------
** BEGIN SSLChannelInfo
** ------------------------------------------------------------
*/
#ifndef SSLChannelInfo
typedef struct SSLChannelInfoStr {
    unsigned long            length;
    unsigned int             protocolVersion;
    unsigned int             cipherSuite;

    /* server authentication info */
    unsigned long             authKeyBits;

    /* key exchange algorithm info */
    unsigned long             keaKeyBits;

    /* session info */
    unsigned long             creationTime;          /* seconds since Jan 1, 1970 */
    unsigned long             lastAccessTime;        /* seconds since Jan 1, 1970 */
    unsigned long             expirationTime;        /* seconds since Jan 1, 1970 */
    unsigned long             sessionIDLength;       /* up to 32 */
    unsigned char             sessionID    [32];
} SSLChannelInfo;
#endif
/*
** ------------------------------------------------------------
** END SSLChannelInfo
** ------------------------------------------------------------
*/


/*
** ------------------------------------------------------------
** BEGIN VA ERRORS
** ------------------------------------------------------------
*/
typedef struct {
long ERROR;
int STATUS;
} VA_OCSP_VR;

typedef struct {
char *revoked;
char *unknown;
char *unreachable;
char *internal;
char *revoked_name;
char *unknown_name;
char *unreachable_name;
char *internal_name;
} VA_ERRORS;
/*
** ------------------------------------------------------------
** END VA ERRORS
** ------------------------------------------------------------
*/

typedef struct {
char	*m_pszHost;
char 	*m_pszPort;
char 	*m_pszPath;
int 	m_iUseSSL;
} VA_RESPONDER;

typedef struct {
DIR 		*m_ptrDir;
struct dirent 	*m_ptrBuffer;
char 		*m_pszPath;
char 		*m_pszType; 
} DIRECTORY_CTX;


/*
** ------------------------------------------------------------
** BEGIN COMMON CONSTS
** ------------------------------------------------------------
*/
#define VA_PEM_BEGIN_CERT 		"-----BEGIN CERTIFICATE-----\n"
#define VA_PEM_END_CERT 		"-----END CERTIFICATE-----\n"
#define VA_PEM_LINE_LEN			64
#define VA_PEM_SAFETY			256
#define VA_PEM_LINES(BUFFER)		(strlen( BUFFER ) / VA_PEM_LINE_LEN) + ( strlen( BUFFER ) % VA_PEM_LINE_LEN == 0 ? 0 : 1 )
#define VA_PEMFILE_SUFIX		".cer"
#define VA_MAX_VALIDITY_PERIOD		(5 * 60)

#define VA_CONFIG_FILE			"va-config-file"
#define VA_OCSP_VR_INIT(ST)		(ST.ERROR=0, ST.STATUS=-1)
#define VA_OCSP_VR_SET(ST,E,S) 		(ST.ERROR= E, ST.STATUS= S)
#define VA_OCSP_VR_SET_ERROR(ST,E) 	(ST.ERROR= E)
#define VA_OCSP_VR_SET_STATUS(ST,S) 	(ST.STATUS= S)
#define VA_OCSP_VR_ERROR(ST) 		(ST.ERROR)
#define VA_OCSP_VR_STATUS(ST) 		(ST.STATUS)
#define VA_OCSP_VR_ISOK(ST) 		((ST.ERROR == 0 && ST.STATUS == 0) ? 1 : 0 ) 
#define IFNOTNULL_FREE(PTR)		if( m_pszBuffer ) free( m_pszBuffer )
#define	EXEC_TIME_MILLI(B,E)		((unsigned long)((E-B)*1E3/CLOCKS_PER_SEC))
#define	EXEC_TIME_MICRO(B,E)		((unsigned long)((E-B)*1E6/CLOCKS_PER_SEC))
#define	EXEC_TIME_TICKS(B,E)		((unsigned long)((E-B)))
/*
** ------------------------------------------------------------
** END COMMON CONSTS
** ------------------------------------------------------------
*/

/*
** ------------------------------------------------------------
** BEGIN PROPERTIES
** ------------------------------------------------------------
*/
#define _PROPERTIE_MAX_LEN	1024
typedef struct
{
	char *m_szName;
	char *m_szValue;
} _PROPERTIES;
/*
** ------------------------------------------------------------
** END PROPERTIES
** ------------------------------------------------------------
*/


/*
** ------------------------------------------------------------
** BEGIN Custon Configuration options 
** ------------------------------------------------------------
*/
#define VA_OCSPSVR_URL		"VA_OCSPSVR_URL"  
#define	VA_TRUSTED_CAS        	"VA_TRUSTED_CAS"  
#define	VA_OCSPD_CERT         	"VA_OCSPD_CERT"   
#define	VA_CACHE_SIZE         	"VA_CACHE_SIZE"   
#define	VA_CACHE_MAXAGE        	"VA_CACHE_MAXAGE"   
#define	VA_ERROR_DOCROOT      	"VA_ERROR_DOCROOT"
#define	VA_ERROR_REVOKED      	"VA_ERROR_REVOKED"
#define	VA_ERROR_UNKNOWN      	"VA_ERROR_UNKNOWN"
#define	VA_ERROR_UNREACHABLE	"VA_ERROR_UNREACHABLE"
#define	VA_ERROR_INTERNAL     	"VA_ERROR_INTERNAL"

_PROPERTIES g_objProperties[]= 
{
	{VA_OCSPSVR_URL,NULL},
	{VA_TRUSTED_CAS,NULL},
	{VA_OCSPD_CERT,NULL},
	{VA_CACHE_SIZE,NULL},
	{VA_CACHE_MAXAGE,NULL},
	{VA_ERROR_DOCROOT,NULL},
	{VA_ERROR_REVOKED,NULL},
	{VA_ERROR_UNKNOWN,NULL},
	{VA_ERROR_UNREACHABLE,NULL},
	{VA_ERROR_INTERNAL,NULL},
	{NULL,NULL}
};
/*
** ------------------------------------------------------------
** END Custon Configuration options 
** ------------------------------------------------------------
*/


/*
** ------------------------------------------------------------
** BEGIN NSAPI OCSP CACHE API MUTEX
** ------------------------------------------------------------
*/
#ifdef _BUILD_NSAPI_

#define		VA_CACHE_INIT_LOCK()	(g_objMUTEX=crit_init())
#define		VA_CACHE_LOCK()		(crit_enter(g_objMUTEX))
#define		VA_CACHE_UNLOCK()	(crit_exit(g_objMUTEX))

#endif
/*
** ------------------------------------------------------------
** END NSAPI OCSP CACHE API MUTEX
** ------------------------------------------------------------
*/


/*
** ------------------------------------------------------------
** BEGIN OCSP CACHE API
** ------------------------------------------------------------
*/
#define	VA_SSL_SESSIONID_MAXAGE	120
#define	VA_SSL_SESSIONID_CACHE	64
#define	VA_SSL_SESSIONID_SIZE	128

typedef struct
{
	int	m_iSize;
	int 	m_iMaxAge;
} VA_CACHE_CONFIG;

#define VA_CACHE_CFG_SET(ST, S, M)	( ST.m_iSize= S, ST.m_iMaxAge= M )
#define VA_CACHE_ENABLED(ST)		( (ST.m_iSize != -1) ? 1 : 0 )

typedef struct
{
	unsigned int 	SSL_INDEX;
	unsigned char 	SSL_SESSIONID[VA_SSL_SESSIONID_CACHE][VA_SSL_SESSIONID_SIZE];
	unsigned long	SSL_LASTTIME[VA_SSL_SESSIONID_CACHE];
} VA_SSLID_CACHE;


/*
** ------------------------------------------------------------
** END OCSP CACHE API
** ------------------------------------------------------------
*/


/*
** ------------------------------------------------------------
** BEGIN GLOBALS
** ------------------------------------------------------------
*/
X509 		*m_objVACertificate= NULL;
STACK_OF(X509) 	*m_objTrustedCAs= NULL;

VA_RESPONDER 	m_objVA_RESPONDER;
VA_ERRORS	m_objVA_ERRORS;


VA_CACHE_CONFIG	g_objSSLID_CONFIG;
VA_SSLID_CACHE 	g_objSSLID_CACHE;


#ifdef _BUILD_NSAPI_
CRITICAL 	g_objMUTEX= NULL;
#endif
/*
** ------------------------------------------------------------
** END GLOBALS
** ------------------------------------------------------------
*/


void 		va_startup( char *pszProperties );
void 		va_load_error_pages(_PROPERTIES *objProperties, VA_ERRORS *objErrors);
void 		va_openssl_init(void);
void 		va_responder_reset(VA_RESPONDER *objValue);
int 		va_responder_config(char *pszURL, VA_RESPONDER *objValue);
X509* 		va_read_cert_from_file(char *pszPath);
X509* 		va_read_cert_from_memory(char *pszX509Stream);
void 		va_load_ca_stack( STACK_OF(X509) **objValue, X509 *objX509 );
void 		va_load_issuer_ca(STACK_OF(X509) **objValue, char *pszPath);
int 		va_issuer_count(STACK_OF(X509) **objValue);
static int	va_build_ocsp_request(OCSP_REQUEST **objReq, X509 *objCert, X509 *objIssuer,STACK_OF(OCSP_CERTID) *objIds);
void 		va_ocsp_request(OCSP_REQUEST *objReq, OCSP_RESPONSE **objResp, VA_RESPONDER objValue );
VA_OCSP_VR 	va_ocsp_response_verify(OCSP_RESPONSE *objResp, STACK_OF(OCSP_CERTID) *objIds);
VA_OCSP_VR 	va_check_status(STACK_OF(X509) *objTrustedCAs, VA_RESPONDER objValue, char *pszAuthCert);
void 		va_canonical_pem( char * pszBuffer, char *pszOutput );
int 		va_canonical_length( char * pszBuffer );

/*
** ------------------------------------------------------------
** BEGIN Filesystem directory api
** ------------------------------------------------------------
*/
void 		OpenDirectory(DIRECTORY_CTX *objContext, char *pszPath, char *pszType);
void 		CloseDirectory(DIRECTORY_CTX *objContext);
char*		GetNextDirectoryEntry(DIRECTORY_CTX *objContext);
char* 		GetFullPath(char *pszPath, char *pszFile);
/*
** ------------------------------------------------------------
** END Filesystem directory api
** ------------------------------------------------------------
*/

long		filesize(FILE *fp);
char* 		LoadFile2Buffer(char *pszPath);
void 		RemoveTrailing(char *pszString);

/*
** ------------------------------------------------------------
** BEGIN Properties api
** ------------------------------------------------------------
*/
char 		*GetPropertie(char *pszName, _PROPERTIES *objProperties);
void 		LoadProperties(char *pszPath, _PROPERTIES *objProperties);
/*
** ------------------------------------------------------------
** END Properties api
** ------------------------------------------------------------
*/

#ifdef _BUILD_NSAPI_

void 		va_send_error(pblock *pb, Session *sn, Request *rq, char *pszName, char *pszBuffer);
void 		va_nsapi_dump_pblock(pblock *objValue);

#endif

void 		va_cache_init(VA_SSLID_CACHE *objCache);
int 		va_cache_isfree(unsigned long ulValue);
int 		va_cache_isexpired(unsigned long ulValue);
int 		va_cache_findslot(VA_SSLID_CACHE *objCache);
void 		va_cache_add(VA_SSLID_CACHE *objCache, char *objSessionID, int iLength);
int 		va_cache_exists(VA_SSLID_CACHE *objCache, char *objSessionID, int iLength);

void print_name(BIO *out, char *title, X509_NAME *nm, unsigned long lflags);


/*
** ------------------------------------------------------------
** BEGIN Simple standalone cache api tester
** ------------------------------------------------------------
*/
#ifdef _BUILD_CACHE_
int main(int argc, char **argv)
{
	int m_iIndex= 0;
	char *m_pszSSLID0= "12345GHIJKABCDFGHIJKABCDFGHIJKABCDFGHIJKZZZZ";
	char *m_pszSSLID1= "ABCDFGHIJKABCDFGHIJKABCDFGHIJKABCDFGHIJKZZZZ";
	
	VA_SSLID_CACHE m_objSSLID_CACHE;
	va_cache_init(&m_objSSLID_CACHE);
	
	for(m_iIndex= 0; m_iIndex < 32; m_iIndex++) {
		va_cache_add(&m_objSSLID_CACHE,m_pszSSLID1,strlen(m_pszSSLID1));
	}
	va_cache_add(&m_objSSLID_CACHE,m_pszSSLID0,strlen(m_pszSSLID0));
	
	for(m_iIndex= 0; m_iIndex < (VA_SSL_SESSIONID_CACHE*1.5); m_iIndex++) {
		va_cache_add(&m_objSSLID_CACHE,m_pszSSLID1,strlen(m_pszSSLID1));
	}
	
	if( va_cache_exists(&m_objSSLID_CACHE,m_pszSSLID0,strlen(m_pszSSLID0)) == 1 ) {
			printf("cache entry found!\n");
	}
	
}
#endif
/*
** ------------------------------------------------------------
** END Simple standalone cache api tester
** ------------------------------------------------------------
*/


/*
** ------------------------------------------------------------
** BEGIN OCSP client test main proc
** ------------------------------------------------------------
*/
#ifdef _BUILD_MAIN_
BIO *out= NULL;
int main(int argc, char **argv)
{
	int	 	m_iIndex= 0;
	VA_OCSP_VR 	m_stVA_OCSP_VR;
	char  		*m_pszCertificate= NULL;
	char  		*m_pszTestCert= 
"MIICxTCCAi6gAwIBAgIBBDANBgkqhkiG9w0BAQQFADCBiTELMAkGA1\
UEBhMCZXMxDzANBgNVBAgTBm1hZHJpZDEPMA0GA1UEBxMGbWFkcmlkM\
RMwEQYDVQQKEwpzZWctc29jaWFsMRAwDgYDVQQLEwdzZXJ2ZXJzMRAw\
DgYDVQQDEwdyb290IGNhMR8wHQYJKoZIhvcNAQkBFhBjYUBzZWctc29\
jaWFsLmVzMB4XDTA3MDEzMDE4MjIyNFoXDTA4MDEzMDE4MjIyNFowSj\
EZMBcGA1UEAxMQYW50b25pbyByZXZvY2FkbzEtMCsGCSqGSIb3DQEJA\
RYeYW50b25pby5yZXZvY2Fkb0BzZWctc29jaWFsLmVzMIGfMA0GCSqG\
SIb3DQEBAQUAA4GNADCBiQKBgQC+T0cZoA4f7T1VV6LEvDU9r+uHri1\
UtDMRupb3cFtM0jrvfqb4c3A7xrwFyn+bc/+rZgE16Goanarr7RPlzS\
wIYFSjgAu1+N//i1/Nsjv8KfgzqtixtAktAkhEXiml2n7bhoLqmnt0e\
RRp5r6Y0lhv9WJEKG9fQHaN82ETmaRDbwIDAQABo3sweTApBgNVHREE\
IjAggR5hbnRvbmlvLnJldm9jYWRvQHNlZy1zb2NpYWwuZXMwDAYDVR0\
TAQH/BAIwADAfBgNVHSMEGDAWgBQu7rGsDlOOoDm7QytaFpxPgvITLD\
AdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwQwDQYJKoZIhvcNA\
QEEBQADgYEAck6bKBO80Ayb4A8ogEuIk2FdvHR8tRus7t98U4rdG5VA\
0LjsXyzF2n63uSt8isRKGj18SbxBLlKBzfMjvb18lWSzDoeG6tRJyMw\
UZaH2/t9tx4ANqPfYGonx62Ne5f6gGicl99y/v3MouGrjC64PkBu8bL\
xJub5HMqnOXBaCuA8=";

	
	
	if( ! (m_pszCertificate= LoadFile2Buffer( argv[2] )) ) {
		m_pszCertificate= m_pszTestCert;
	}
	
	va_startup( argv[1] );
	out= BIO_new_fp(stdout,BIO_NOCLOSE|BIO_FP_TEXT);
	fprintf(stdout,"OCSP RESPONER(%s) CAs(%d)\n", m_objVA_RESPONDER.m_pszHost, va_issuer_count(&m_objTrustedCAs));
	
	for( m_iIndex= 0; m_iIndex< 100000; m_iIndex++ ) {	
		VA_OCSP_VR_INIT( m_stVA_OCSP_VR );
		m_stVA_OCSP_VR= va_check_status( m_objTrustedCAs, m_objVA_RESPONDER, m_pszCertificate);
		printf("(%d) (ERROR=%d) (STATUS= %d) (->%d)\n",m_iIndex,VA_OCSP_VR_ERROR(m_stVA_OCSP_VR), VA_OCSP_VR_STATUS(m_stVA_OCSP_VR), VA_OCSP_VR_ISOK(m_stVA_OCSP_VR) );
		if( VA_OCSP_VR_STATUS(m_stVA_OCSP_VR) == 1 ) {
			printf("%s",m_objVA_ERRORS.revoked);
		}
	}		

}
#endif
/*
** ------------------------------------------------------------
** END OCSP client test main proc
** ------------------------------------------------------------
*/

/*
** ------------------------------------------------------------
** BEGIN OCSP CACHE API
** ------------------------------------------------------------
*/

/*
** ----------------------------------------------------------------------
** @name va_cache_init
** 
** @param 
** @return 
** 
** @note 	
**		
** ----------------------------------------------------------------------
*/
void va_cache_init(VA_SSLID_CACHE *objCache)
{
	int m_iIndex= 0;
	for(m_iIndex= 0; m_iIndex< VA_SSL_SESSIONID_CACHE; m_iIndex++) {
		memset( (void *) objCache->SSL_SESSIONID[ m_iIndex ], 0, VA_SSL_SESSIONID_SIZE * sizeof(unsigned char) );
		objCache->SSL_LASTTIME[ m_iIndex ]= -1;
	}
	objCache->SSL_INDEX= 0;
}

/*
** ----------------------------------------------------------------------
** @name va_cache_isfree
** 
** @param 
** @return 
** 
** @note 	
**		
** ----------------------------------------------------------------------
*/
int va_cache_isfree(unsigned long ulValue)
{
	return( ( ulValue == -1 ) ? 1 : 0 );
}

/*
** ----------------------------------------------------------------------
** @name va_cache_isexpired
** 
** @param 
** @return 
** 
** @note 	
**		
** ----------------------------------------------------------------------
*/
int va_cache_isexpired(unsigned long ulValue)
{
	return(  ((time(NULL) - ulValue ) > VA_SSL_SESSIONID_MAXAGE) ? 1 : 0 );	
}

/*
** ----------------------------------------------------------------------
** @name va_cache_findslot
** 
** @param 
** @return 
** 
** @note 	
**		
** ----------------------------------------------------------------------
*/
int va_cache_findslot(VA_SSLID_CACHE *objCache)
{
	int m_iIndex= 0;
	int m_iSlot= -1;
			
	for(m_iIndex= objCache->SSL_INDEX; m_iIndex< VA_SSL_SESSIONID_CACHE; m_iIndex++) {
		if( va_cache_isexpired( objCache->SSL_LASTTIME[ m_iIndex ] ) || va_cache_isfree( objCache->SSL_LASTTIME[ m_iIndex ] ) ) {
			m_iSlot= m_iIndex;
			break;
		}
	}
	return( m_iSlot );
}

/*
** ----------------------------------------------------------------------
** @name va_cache_add
** 
** @param 
** @return 
** 
** @note 	
**		
** ----------------------------------------------------------------------
*/
void va_cache_add(VA_SSLID_CACHE *objCache, char *objSessionID, int iLength)
{
	int m_iSlot= -1;

	if( (m_iSlot= va_cache_findslot(objCache)) != -1 ) {
		memcpy( (void *) objCache->SSL_SESSIONID[ m_iSlot ], objSessionID, iLength );
		objCache->SSL_LASTTIME[ m_iSlot ]= time(NULL);
		objCache->SSL_INDEX= m_iSlot;objCache->SSL_INDEX++;
	} else {
		objCache->SSL_INDEX= 0;		
	}
}

/*
** ----------------------------------------------------------------------
** @name va_cache_exists
** 
** @param 
** @return 
** 
** @note 	
**		
** ----------------------------------------------------------------------
*/
int va_cache_exists(VA_SSLID_CACHE *objCache, char *objSessionID, int iLength)
{
	int m_iFound= 0;
	int m_iIndexF= 0;
	int m_iIndexR= 0;
			
	for(m_iIndexF= 0, m_iIndexR= VA_SSL_SESSIONID_CACHE; m_iIndexF< VA_SSL_SESSIONID_CACHE, m_iIndexR> 0; m_iIndexF++, m_iIndexR--) {
		if( memcmp( objCache->SSL_SESSIONID[ m_iIndexF ], objSessionID, iLength ) == 0  && !va_cache_isexpired(objCache->SSL_LASTTIME[ m_iIndexF ]) ) {
			//objCache->SSL_LASTTIME[ m_iIndex ]= time(NULL);
			m_iFound= 1;
			break;
		}
		if( memcmp( objCache->SSL_SESSIONID[ m_iIndexR ], objSessionID, iLength ) == 0  && !va_cache_isexpired(objCache->SSL_LASTTIME[ m_iIndexR ]) ) {
			//objCache->SSL_LASTTIME[ m_iIndex ]= time(NULL);
			m_iFound= 1;
			break;
		}
	}
	return( m_iFound );
}

/*
** ------------------------------------------------------------
** END OCSP CACHE API
** ------------------------------------------------------------
*/

void print_name(BIO *out, char *title, X509_NAME *nm, unsigned long lflags)
{
  int half_buf_size = 256;
  char* buf = (char*) OPENSSL_malloc(half_buf_size * 2);
  int len1, len2;
  char mline = 0;
  int indent = 0;

  if(title) BIO_puts(out, title);
  if((lflags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE) {
    mline = 1;
    indent = 4;
  }
  if(lflags == XN_FLAG_COMPAT) {   
	while(1) {
	X509_NAME_oneline(nm, buf, half_buf_size);
      len1 = strlen(buf);
      X509_NAME_oneline(nm, buf, half_buf_size*2);
      len2 = strlen(buf);
      if(len1 == len2)
    break;
      half_buf_size *= 2;
      buf = OPENSSL_realloc(buf, half_buf_size * 2);
    }
    BIO_puts(out,buf);
    BIO_puts(out, "\n");
  } else {
    if(mline) BIO_puts(out, "\n");
    X509_NAME_print_ex(out, nm, indent, lflags);
    BIO_puts(out, "\n");
  }
}

/*
** ----------------------------------------------------------------------
** BEGIN NSAPI CODE
** ----------------------------------------------------------------------
*/
#ifdef _BUILD_NSAPI_
/*
** ----------------------------------------------------------------------
** @name va_init
** 
** @param 
** @return 
** 
** @note 	
**		
** ----------------------------------------------------------------------
*/
#ifdef __cplusplus
extern "C"
#endif
NSAPI_PUBLIC int va_nsapi_init(pblock *pb, Session *sn, Request *rq)
{
	int m_iRC= REQ_PROCEED;
	int m_iIndx= 0;
	char *m_pszConfigFile= pblock_findval( VA_CONFIG_FILE, pb);
	
	if( m_pszConfigFile ) {
		va_startup( m_pszConfigFile );
		if( GetPropertie(VA_CACHE_SIZE,g_objProperties) && GetPropertie(VA_CACHE_MAXAGE,g_objProperties) ) {
			VA_CACHE_CFG_SET(g_objSSLID_CONFIG, atoi(GetPropertie(VA_CACHE_SIZE,g_objProperties)), atoi(GetPropertie(VA_CACHE_MAXAGE,g_objProperties)) );
			if( VA_CACHE_ENABLED( g_objSSLID_CONFIG ) ) {
				VA_CACHE_INIT_LOCK();
				va_cache_init(&g_objSSLID_CACHE);		
			} else {
				log_error(LOG_WARN, "[vacert]", NULL, NULL,"ssl-id cache disabled.");
			}
		}
	}
	else {
		m_iRC= REQ_ABORTED;
	}
	return( m_iRC );
}

/*
** ----------------------------------------------------------------------
** @name va_ocsp_auth
** 
** @param 
** @return 
** 
** @note 	
**		
** ----------------------------------------------------------------------
*/
#ifdef __cplusplus
extern "C"
#endif
NSAPI_PUBLIC int va_ocsp_auth(pblock *pb, Session *sn, Request *rq)
{
	FuncPtr m_ptrFunction= NULL;
	VA_OCSP_VR m_stVA_OCSP_VR;
	int m_iRC= REQ_NOACTION;
	char *m_pszAuthCert= NULL;
	char *m_pszSSL= NULL;
	
	char *m_pszPath= NULL;
	char *m_pszErrorRoot= NULL;
	long m_lRootLength= 0;
	

	if( (m_pszPath= pblock_findval("path", rq->vars)) ) {
		m_pszErrorRoot= GetPropertie( VA_ERROR_DOCROOT, g_objProperties );
		if( ( m_lRootLength= strlen( m_pszErrorRoot ) ) <= strlen( m_pszPath ) )
			if( strncmp( m_pszErrorRoot, m_pszPath, m_lRootLength ) == 0 )
				return( REQ_NOACTION );
	}

	if( !( m_pszSSL= pblock_findval("ssl-id", sn->client) ) ) {
		log_error(LOG_WARN, "[vacert]", NULL, NULL,"internal error: ssl-id");
		va_send_error(pb, sn, rq, m_objVA_ERRORS.internal_name, m_objVA_ERRORS.internal); 
		return( REQ_ABORTED );
	}
	
	
	if( VA_CACHE_ENABLED( g_objSSLID_CONFIG ) ) {
		VA_CACHE_LOCK();
		if( va_cache_exists( &g_objSSLID_CACHE, m_pszSSL, strlen(m_pszSSL) ) ) {
			log_error(LOG_VERBOSE, "[vacert]", NULL, NULL,"cache hit: %s",pblock_findval("user_dn", sn->client));
			VA_CACHE_UNLOCK();
			return( REQ_NOACTION );
		} else {
			log_error(LOG_WARN, "[vacert]", NULL, NULL,"cache miss: %s",pblock_findval("user_dn", sn->client));
			VA_CACHE_UNLOCK();
		}
	}
	
	
	if( ! (m_pszAuthCert= pblock_findval("auth-cert", rq->vars)) ) {
		if( (m_ptrFunction= func_find("get-client-cert")) ) {
			(*m_ptrFunction) (pb,sn,rq);
			m_pszAuthCert= pblock_findval("auth-cert", rq->vars);
		}
	}
			
	if( m_pszAuthCert ) {
		VA_OCSP_VR_INIT( m_stVA_OCSP_VR );
		m_stVA_OCSP_VR= va_check_status( m_objTrustedCAs, m_objVA_RESPONDER, m_pszAuthCert);
		
		if( !VA_OCSP_VR_ISOK(m_stVA_OCSP_VR) ) {
			m_iRC= REQ_ABORTED;
			switch( VA_OCSP_VR_ERROR(m_stVA_OCSP_VR) ) {
				case 0: {
					switch( VA_OCSP_VR_STATUS(m_stVA_OCSP_VR) ) {
						case 1: {
							log_error(LOG_WARN, "[vacert]", NULL, NULL,"certificate status revoked: %s",pblock_findval("user_dn", sn->client));
							va_send_error(pb, sn, rq, m_objVA_ERRORS.revoked_name, m_objVA_ERRORS.revoked); 
							break;
						}
						
						case 2: {
							log_error(LOG_WARN, "[vacert]", NULL, NULL,"certificate status unknown: %s",pblock_findval("user_dn", sn->client));
							va_send_error(pb, sn, rq, m_objVA_ERRORS.unknown_name, m_objVA_ERRORS.unknown); 
							break;
						}
						
						default: {
							log_error(LOG_WARN, "[vacert]", NULL, NULL,"internal error: invalid status");
							va_send_error(pb, sn, rq, m_objVA_ERRORS.internal_name, m_objVA_ERRORS.internal); 
							break;
						}
					}
					
					break;
				}
				
				case 537342055: {
					log_error(LOG_WARN, "[vacert]", NULL, NULL,"internal error: communication error");
					va_send_error(pb, sn, rq, m_objVA_ERRORS.unreachable_name, m_objVA_ERRORS.unreachable); 
					break;
				}
				
				default: {
					log_error(LOG_WARN, "[vacert]", NULL, NULL,"internal error: other errors");
					va_send_error(pb, sn, rq, m_objVA_ERRORS.internal_name, m_objVA_ERRORS.internal); 
					break;
				}
			}
		} else {
			if( VA_CACHE_ENABLED( g_objSSLID_CONFIG ) ) {
				VA_CACHE_LOCK();
				va_cache_add( &g_objSSLID_CACHE, m_pszSSL, strlen(m_pszSSL) );
				VA_CACHE_UNLOCK();
			}
		} 
	}
	else {
		log_error(LOG_WARN, "[vacert]", NULL, NULL,"internal error: no auth-cert");
		va_send_error(pb, sn, rq, m_objVA_ERRORS.internal_name, m_objVA_ERRORS.internal); 
		m_iRC= REQ_ABORTED;
	}
	
	
			
	
	return( m_iRC );
}

/*
** ----------------------------------------------------------------------
** @name va_send_error
** 
** @param 
** @return 
** 
** @note 	
**		
** ----------------------------------------------------------------------
*/
#ifdef __cplusplus
extern "C"
#endif
void va_send_error(pblock *pb, Session *sn, Request *rq, char *pszName, char *pszBuffer) 
{

	param_free(pblock_remove("content-type", rq->srvhdrs));
	param_free(pblock_remove("content-length", rq->srvhdrs));
	param_free(pblock_remove("path", rq->vars));
	protocol_status(sn, rq, PROTOCOL_UNAUTHORIZED, NULL);
	pblock_nvinsert("content-type", "text/html", rq->srvhdrs);
	pblock_nninsert("content-length", strlen(pszBuffer), rq->srvhdrs);
	pblock_nvinsert("path", pszName, rq->vars);
	
	if(protocol_start_response(sn, rq) != REQ_NOACTION)
	{
		(void) net_write(sn->csd, pszBuffer, strlen(pszBuffer) );
	}
}	

void va_nsapi_dump_pblock(pblock *objValue)
{
	int m_iIndex= 0;
	struct pb_entry	*m_objEntry;

	for( m_iIndex=0; m_iIndex< objValue->hsize; m_iIndex++) {
		for( m_objEntry= objValue->ht[m_iIndex]; m_objEntry; m_objEntry= m_objEntry->next) 
		{
			printf("NAME=(%s) VALUE=(%s)\n",m_objEntry->param->name,m_objEntry->param->value);
		}
	}
}
#endif
/*
** ----------------------------------------------------------------------
** END NSAPI CODE
** ----------------------------------------------------------------------
*/

/*
** ----------------------------------------------------------------------
** @name OpenDirectory
** 
** @param 
** @return 
** 
** @note 	
**		
** ----------------------------------------------------------------------
*/
void OpenDirectory(DIRECTORY_CTX *objContext, char *pszPath, char *pszType)
{
	long m_lNAME_MAX= 0;
	
	objContext->m_ptrDir= NULL;
	objContext->m_ptrBuffer= NULL;
	objContext->m_pszPath= NULL;
	objContext->m_pszType= NULL; 
	
	objContext->m_pszPath= (char *) malloc( strlen(pszPath) );
	objContext->m_pszType= (char *) malloc( strlen(pszType) );
	strcpy( objContext->m_pszPath, pszPath );
	strcpy( objContext->m_pszType, pszType );
	
	objContext->m_ptrDir= opendir( objContext->m_pszPath );
		
	if ( (m_lNAME_MAX= pathconf( objContext->m_pszPath, _PC_NAME_MAX))  > 0 ) {
		if( ! (objContext->m_ptrBuffer= (struct dirent *) malloc( offsetof(struct dirent, d_name) + m_lNAME_MAX + 1) ) ) {
			CloseDirectory( objContext );
		}
	}
	else {
		CloseDirectory( objContext );
	}
	
}

/*
** ----------------------------------------------------------------------
** @name GetNextDirectoryEntry
** 
** @param 
** @return 
** 
** @note 	
**		
** ----------------------------------------------------------------------
*/
char * GetNextDirectoryEntry(DIRECTORY_CTX *objContext)
{
	char *m_pszBuffer= NULL;
	struct dirent *m_ptrEntry= NULL; 
	
	if( objContext->m_ptrDir ) {
		while( readdir_r( objContext->m_ptrDir, objContext->m_ptrBuffer, &m_ptrEntry ) == 0 && m_ptrEntry) {
			
			if( objContext->m_pszType ) 
            		{
            			if( strlen( objContext->m_pszType ) > strlen( m_ptrEntry->d_name ) ) continue;
            			m_pszBuffer= ( m_ptrEntry->d_name+(strlen(m_ptrEntry->d_name)-strlen(objContext->m_pszType)) );
            		        if( strcmp( m_pszBuffer,objContext->m_pszType ) == 0 ) {
            		        	return( m_ptrEntry->d_name );
            		        }
            		}
            		else {
				return( m_ptrEntry->d_name );
			}
		}
	}
	return( NULL );	
}

/*
** ----------------------------------------------------------------------
** @name CloseDirectory
** 
** @param 
** @return 
** 
** @note 	
**		
** ----------------------------------------------------------------------
*/
void CloseDirectory(DIRECTORY_CTX *objContext)
{
	if( objContext->m_ptrDir ) closedir( objContext->m_ptrDir );
	if( objContext->m_ptrBuffer ) free( objContext->m_ptrBuffer );
	if( objContext->m_pszPath ) free( objContext->m_pszPath );
	if( objContext->m_pszType ) free( objContext->m_pszType );
	objContext->m_ptrDir= NULL;
	objContext->m_ptrBuffer= NULL;
	objContext->m_pszPath= NULL;
	objContext->m_pszType= NULL;
}

/*
** ----------------------------------------------------------------------
** @name GetFullPath
** 
** @param 
** @return
** @note 	
**		
** ----------------------------------------------------------------------
*/
char* GetFullPath(char *pszPath, char *pszFile)
{
	long m_lSize= 0;
	char *m_pszFullPath= NULL;
	
	m_lSize= strlen( pszPath ) + strlen( pszFile ) + 255;
	
	if( (m_pszFullPath= (char *) malloc( m_lSize )) ) {
		memset( m_pszFullPath, 0, m_lSize );
		sprintf( m_pszFullPath,"%s/%s",pszPath, pszFile ); 
	}
	return( m_pszFullPath );
}

/*
** ----------------------------------------------------------------------
** @name filesize
** 
** @param 
** @return 
** 
** @note 	
**		
** ----------------------------------------------------------------------
*/
long filesize(FILE *fp)
{
     long curpos;
     long length;
     curpos= ftell(fp);
     fseek(fp, 0L, SEEK_END);
     length= ftell(fp);
     fseek(fp, curpos, SEEK_SET);
     return( length );
}

/*
** ----------------------------------------------------------------------
** @name LoadCertificateFile
** 
** @param 
** @return 
** 
** @note 	
**		
** ----------------------------------------------------------------------
*/
char* LoadFile2Buffer(char *pszPath)
{
	FILE *m_fpFile= NULL;
	char *m_pszBuffer= NULL; 
	long m_lSize= 0;

	if( (m_fpFile= fopen(pszPath,"r")) != NULL) {
		m_lSize= filesize(m_fpFile);
		m_pszBuffer= (char *) malloc( m_lSize + 255 );
		if( m_pszBuffer ) {
			memset(m_pszBuffer, 0,  m_lSize + 255 );
			fread( m_pszBuffer, m_lSize, 1, m_fpFile );
		}
		fclose( m_fpFile );
	}
	return( m_pszBuffer );
}


/*
** ----------------------------------------------------------------------
** @name LoadProperties
** 
** @param 
** @return 
** 
** @note 	
**		
** ----------------------------------------------------------------------
*/
void LoadProperties(char *pszPath, _PROPERTIES *objProperties)
{
	char m_cCTRL= 0;
	FILE *m_fpFile= NULL;
	char *m_szBuffer= (char *) malloc(_PROPERTIE_MAX_LEN);
	int m_iIndx= 0;
	int m_iNLen= 0;

	//
	if( (m_fpFile= fopen(pszPath,"r")) != NULL)
	{
		
		while( (m_cCTRL= fgetc(m_fpFile)) != EOF)
		{
			ungetc(m_cCTRL,m_fpFile);
			memset(m_szBuffer,0,_PROPERTIE_MAX_LEN);
			fgets(m_szBuffer,_PROPERTIE_MAX_LEN,m_fpFile);
			
			RemoveTrailing(m_szBuffer);
			
			for(m_iIndx= 0; objProperties[m_iIndx].m_szName != NULL; m_iIndx++)
			{	
				m_iNLen= strlen(objProperties[m_iIndx].m_szName);
				if( strlen( m_szBuffer ) <= m_iNLen ) continue;
				if(strncasecmp(m_szBuffer,objProperties[m_iIndx].m_szName,m_iNLen) == 0)
				{
					objProperties[m_iIndx].m_szValue= strdup(m_szBuffer+m_iNLen+1);
					break;
				}
			}
		}
	}
	//
	free(m_szBuffer);
	fclose(m_fpFile);
}

/*
** ----------------------------------------------------------------------
** @name GetPropertie
** 
** @param 
** @return 
** 
** @note 	
**		
** ----------------------------------------------------------------------
*/
char *GetPropertie(char *pszName, _PROPERTIES *objProperties)
{	
	int m_iIndx= 0;
	int m_iNLen= 0;
	//
	for(m_iIndx= 0; objProperties[m_iIndx].m_szName != NULL; m_iIndx++)
	{	
		m_iNLen= strlen(objProperties[m_iIndx].m_szName);
		if(strncasecmp(pszName,objProperties[m_iIndx].m_szName,m_iNLen) == 0) break;

	}
	//
	return(objProperties[m_iIndx].m_szValue);
}

/*
** ----------------------------------------------------------------------
** @name RemoveTrailing
** 
** @param 
** @return 
** 
** @note 	
**		
** ----------------------------------------------------------------------
*/
void RemoveTrailing(char *pszString)
{
	int m_iIndx= 0;
	//
	if( strlen(pszString) > 2 ) {
		for(m_iIndx= strlen(pszString); iscntrl( pszString[m_iIndx]); m_iIndx--)
			pszString[m_iIndx]= 0;
	}
}

/*
** ----------------------------------------------------------------------
** @name va_startup
** 
** @param 
** @return
** @note 	
**		
** ----------------------------------------------------------------------
*/
void va_startup( char *pszProperties )
{
	
	va_openssl_init();
	
	LoadProperties( pszProperties, g_objProperties );
	va_load_error_pages( g_objProperties, &m_objVA_ERRORS );
	va_responder_reset( &m_objVA_RESPONDER );	
	va_responder_config(GetPropertie(VA_OCSPSVR_URL,g_objProperties), &m_objVA_RESPONDER );
	va_load_issuer_ca( &m_objTrustedCAs, GetPropertie(VA_TRUSTED_CAS,g_objProperties) );
}

/*
** ----------------------------------------------------------------------
** @name va_load_error_pages
** 
** @param 
** @return
** @note 	
**		
** ----------------------------------------------------------------------
*/
void va_load_error_pages(_PROPERTIES *objProperties, VA_ERRORS *objErrors)
{
	objErrors->revoked= NULL;
	objErrors->unknown= NULL;
	objErrors->unreachable= NULL;
	objErrors->internal= NULL;
	objErrors->revoked_name= NULL;
	objErrors->unknown_name= NULL;
	objErrors->unreachable_name= NULL;
	objErrors->internal_name= NULL;

	objErrors->revoked_name= GetFullPath( GetPropertie( VA_ERROR_DOCROOT, objProperties), GetPropertie( VA_ERROR_REVOKED, objProperties) );
	objErrors->unknown_name= GetFullPath( GetPropertie( VA_ERROR_DOCROOT, objProperties), GetPropertie( VA_ERROR_UNKNOWN, objProperties) );
	objErrors->unreachable_name= GetFullPath( GetPropertie( VA_ERROR_DOCROOT, objProperties), GetPropertie( VA_ERROR_UNREACHABLE , objProperties) );
	objErrors->internal_name= GetFullPath( GetPropertie( VA_ERROR_DOCROOT, objProperties), GetPropertie( VA_ERROR_INTERNAL, objProperties) );
	
	objErrors->revoked= LoadFile2Buffer( objErrors->revoked_name ); 
	objErrors->unknown= LoadFile2Buffer( objErrors->unknown_name );
	objErrors->unreachable= LoadFile2Buffer( objErrors->unreachable_name );
	objErrors->internal= LoadFile2Buffer( objErrors->internal_name ); 
}

/*
** ----------------------------------------------------------------------
** @name va_openssl_init
** 
** @param 
** @return
** @note 	
**		
** ----------------------------------------------------------------------
*/
void va_openssl_init(void)
{
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
}

/*
** ----------------------------------------------------------------------
** @name va_responder_reset
** 
** @param 
** @return
** @note 	
**		
** ----------------------------------------------------------------------
*/
void va_responder_reset(VA_RESPONDER *objValue)
{
	objValue->m_pszHost= NULL;
	objValue->m_pszPort= NULL;
	objValue->m_pszPath= NULL;
	objValue->m_iUseSSL= -1;
}

/*
** ----------------------------------------------------------------------
** @name va_responder_config
** 
** @param 
** @return
** @note 	
**		
** ----------------------------------------------------------------------
*/
int va_responder_config(char *pszURL, VA_RESPONDER *objValue)
{
	return( OCSP_parse_url( pszURL, &(objValue->m_pszHost), &(objValue->m_pszPort), &(objValue->m_pszPath), &(objValue->m_iUseSSL)) );
}

/*
** ----------------------------------------------------------------------
** @name va_read_cert_from_file
** 
** @param pszPath:	
** 
** @note 	
**		
** ----------------------------------------------------------------------
*/
X509* va_read_cert_from_file(char *pszPath)
{
	X509 *m_objX509;
	BIO *m_bioIn= NULL; 		
	FILE *m_fpFile= NULL;
	
	if( (m_fpFile= fopen( pszPath, "r" )) )
	{
		if( (m_bioIn= BIO_new_fp( m_fpFile,BIO_FP_TEXT)) )
		{
			m_objX509= PEM_read_bio_X509(m_bioIn,NULL,NULL,NULL);
			BIO_free( m_bioIn );
		}
		fclose(m_fpFile);
	}
	
	return( m_objX509 );

}

/*
** ----------------------------------------------------------------------
** @name va_read_cert_from_memory
** 
** @param pszPath:	
** 
** @note 	
**		
** ----------------------------------------------------------------------
*/
X509* va_read_cert_from_memory(char *pszX509Stream)
{
	char *m_pszX509= NULL;
	X509 *m_objX509= NULL;
	BIO *m_bioIn= NULL; 		
	
	if( (m_pszX509= (char *) malloc( va_canonical_length( pszX509Stream ))) ) {
		memset( m_pszX509,0, va_canonical_length( pszX509Stream )  ); 
		va_canonical_pem( pszX509Stream, m_pszX509);
		if( m_pszX509 ) {
			if( (m_bioIn= BIO_new(BIO_s_mem())) ) {   
				if( BIO_write( m_bioIn, m_pszX509, strlen(m_pszX509) ) > 0) { 
					m_objX509= PEM_read_bio_X509( m_bioIn,NULL,NULL,NULL); 
				}
				BIO_free( m_bioIn ); 
			}
		}
		free( m_pszX509 );
	}
	return( m_objX509 );
}

/*
** ----------------------------------------------------------------------
** @name va_load_ca_stack
** 
** @param 
** @return
** @note 	
**		
** ----------------------------------------------------------------------
*/
void va_load_ca_stack( STACK_OF(X509) **objValue, X509 *objX509 )
{
	if( !*objValue ) *objValue= sk_X509_new_null();
	sk_X509_push( *objValue, objX509 );
}

/*
** ----------------------------------------------------------------------
** @name va_load_issuer_ca
** 
** @param 
** @return
** @note 	
**		
** ----------------------------------------------------------------------
*/
void va_load_issuer_ca(STACK_OF(X509) **objValue, char *pszPath)
{
	DIRECTORY_CTX m_objContext;
	char *m_pszBuffer= NULL;
	char *m_pszFullPath= NULL;
	X509 *m_objTemp= NULL;
	
	OpenDirectory( &m_objContext,pszPath, VA_PEMFILE_SUFIX );

	while( ( m_pszBuffer= GetNextDirectoryEntry( &m_objContext) ) ) {
		if( (m_pszFullPath= (char *) malloc( strlen( pszPath ) + strlen( m_pszBuffer ) + 255 )) ) {
			memset( m_pszFullPath, 0, strlen( pszPath ) + strlen( m_pszBuffer ) + 255 );
			sprintf( m_pszFullPath,"%s/%s",pszPath, m_pszBuffer ); 
			m_objTemp= va_read_cert_from_file(m_pszFullPath);
			va_load_ca_stack( objValue, m_objTemp );
			
			free( m_pszFullPath );
		}
	}
	
	CloseDirectory( &m_objContext );
	
}

/*
** ----------------------------------------------------------------------
** @name va_issuer_ca_count
** 
** @param 
** @return
** @note 	
**		
** ----------------------------------------------------------------------
*/
int va_issuer_count(STACK_OF(X509) **objValue)
{
	return( sk_X509_num( *objValue ) );
}

/*
** ----------------------------------------------------------------------
** @name va_build_ocsp_request
** 
** @param 
** @return
** @note 	
**		
** ----------------------------------------------------------------------
*/
static int va_build_ocsp_request(OCSP_REQUEST **objReq, X509 *objCert, X509 *objIssuer,STACK_OF(OCSP_CERTID) *objIds)
{
	int		m_iRC= 0;
	OCSP_CERTID 	*m_objId;

	if( objIssuer && objCert ) {
		if( !*objReq ) *objReq= OCSP_REQUEST_new();
		if( *objReq ) {
			m_objId= OCSP_cert_to_id(NULL, objCert, objIssuer);
			if( m_objId && sk_OCSP_CERTID_push( objIds, m_objId) ) {
				if( OCSP_request_add0_id(*objReq, m_objId) ) 
					m_iRC= 1;
				}
		}
	}
	return( m_iRC );
}

/*
** ----------------------------------------------------------------------
** @name va_canonical_pem
** 
** @param 
** @return
** @note 	
**		
** ----------------------------------------------------------------------
*/
void va_canonical_pem( char * pszBuffer, char *pszOutput )
{
	int m_iIndex= 0;
	int m_iIndx= 0;

	//if( strncmp( pszBuffer, VA_PEM_BEGIN_CERT, strlen(VA_PEM_BEGIN_CERT) ) != 0) {
	if( !strstr( pszBuffer, VA_PEM_BEGIN_CERT) ) {
	
		if( !index(pszBuffer,'\n') ) {
			sprintf(pszOutput,VA_PEM_BEGIN_CERT);
			pszOutput+=strlen(VA_PEM_BEGIN_CERT);	
			for(; *pszBuffer!= (char) NULL; pszBuffer++)
			{
				*(pszOutput++)= *pszBuffer;
				if( m_iIndx == 63 ) {
					*(pszOutput++)= '\n';
					m_iIndx= 0;
				}
				else
					m_iIndx++;
			}
			if( m_iIndx != 63 ) {
				*(pszOutput++)= '\n';
			}
			sprintf(pszOutput,VA_PEM_END_CERT); 
		}
		else {
			sprintf(pszOutput,"%s\n%s\n%s",VA_PEM_BEGIN_CERT,pszBuffer,VA_PEM_END_CERT); 			
		}
	}
	else {
		strcpy(pszOutput,pszBuffer); 
	}
}

/*
** ----------------------------------------------------------------------
** @name va_cert2pem_length
** 
** @param 
** @return
** @note 	
**		
** ----------------------------------------------------------------------
*/
int va_canonical_length( char * pszBuffer )
{
	return( strlen(VA_PEM_BEGIN_CERT) + strlen(VA_PEM_END_CERT) + strlen(pszBuffer) + (strlen(pszBuffer) / VA_PEM_LINE_LEN) + ( strlen(pszBuffer) % VA_PEM_LINE_LEN == 0 ? 0 : 1 ) );
}

/*
** ----------------------------------------------------------------------
** @name va_ocsp_request
** 
** @param 
** @return
** @note 	
**		
** ----------------------------------------------------------------------
*/
void va_ocsp_request(OCSP_REQUEST *objReq, OCSP_RESPONSE **objResp, VA_RESPONDER objValue )
{
	BIO *m_objCBIO= NULL;
	
	*objResp= NULL;
	if( (m_objCBIO= BIO_new_connect( objValue.m_pszHost )) ) { 
		BIO_set_conn_port( m_objCBIO, objValue.m_pszPort );
		if( BIO_do_connect( m_objCBIO ) > 0 ) {
			*objResp= OCSP_sendreq_bio( m_objCBIO, objValue.m_pszPath, objReq);
		}
		BIO_free_all( m_objCBIO );
		m_objCBIO= NULL;
	}
}	

/*
** ----------------------------------------------------------------------
** @name va_ocsp_response_time
** 
** @param 
** @return
** @note 	
**		
** ----------------------------------------------------------------------
*/
int va_ocsp_response_time(OCSP_RESPONSE *objResp, STACK_OF(OCSP_CERTID) *objIds)
{
	/*
	if(!OCSP_check_validity( m_objThisUpd, m_objNextUpd, VA_MAX_VALIDITY_PERIOD, -1 ) ) {
				BIO_puts(out, "WARNING: Status times invalid.\n");
				ERR_print_errors(out);
			}
			
			BIO_printf(out, "%s\n", OCSP_cert_status_str(m_iStatus));				
			BIO_puts(out, "\tThis Update: ");
			ASN1_GENERALIZEDTIME_print(out, m_objThisUpd);
			BIO_puts(out, "\n");
			if(m_objNextUpd) {
				BIO_puts(out, "\tNext Update: ");
				ASN1_GENERALIZEDTIME_print(out, m_objNextUpd);
				BIO_puts(out, "\n");
			}

			if (m_iStatus != V_OCSP_CERTSTATUS_REVOKED)
				continue;

			if (m_iReason != -1)
				BIO_printf(out, "\tReason: %s\n",
			OCSP_crl_reason_str(m_iReason));
		*/
}
	
/*
** ----------------------------------------------------------------------
** @name va_ocsp_response_verify
** 
** @param 
** @return
** @note 	
**		
** ----------------------------------------------------------------------
*/
VA_OCSP_VR va_ocsp_response_verify(OCSP_RESPONSE *objResp, STACK_OF(OCSP_CERTID) *objIds)
{
	int m_iIndx= 0;
	int m_iStatus= 0;
	int m_iReason= 0;
	OCSP_CERTID 		*m_objId= NULL;
	OCSP_BASICRESP 		*m_objBasicResp= NULL;
	ASN1_GENERALIZEDTIME 	*m_objRev= NULL;
	ASN1_GENERALIZEDTIME 	*m_objThisUpd= NULL;
	ASN1_GENERALIZEDTIME 	*m_objNextUpd= NULL;
	VA_OCSP_VR		m_stVA_OCSP_VR;
	
	
	VA_OCSP_VR_INIT( m_stVA_OCSP_VR );
	
	m_objBasicResp= OCSP_response_get1_basic( objResp );

	if( m_objBasicResp ) {
		for( m_iIndx= 0; m_iIndx< sk_OCSP_CERTID_num(objIds); m_iIndx++)
		{
			m_objId= sk_OCSP_CERTID_value(objIds, m_iIndx);
			if( !OCSP_resp_find_status( m_objBasicResp, m_objId, &m_iStatus, &m_iReason, &m_objRev, &m_objThisUpd, &m_objNextUpd ) ) continue;
			if (m_iStatus == V_OCSP_CERTSTATUS_REVOKED) break;
		}
	}

	/*
	** Final cleanup
	*/
	if( m_objBasicResp ) OCSP_BASICRESP_free(m_objBasicResp);
	
	VA_OCSP_VR_SET(m_stVA_OCSP_VR, ERR_get_error(),m_iStatus);	
	return( m_stVA_OCSP_VR );
}
	
/*
** ----------------------------------------------------------------------
** @name va_check_status
** 
** @param 
** @return
** @note 	
**		
** ----------------------------------------------------------------------
*/
VA_OCSP_VR va_check_status(STACK_OF(X509) *objTrustedCAs, VA_RESPONDER objValue, char *pszAuthCert)
{
	X509 			*m_objCert= NULL;
	X509 			*m_objIssuer= NULL;
	X509_NAME 		*m_objName= NULL;
	OCSP_REQUEST 		*m_objReq= NULL;
	OCSP_RESPONSE 		*m_objResp= NULL;
	STACK_OF(OCSP_CERTID) 	*m_objIds= NULL;
	VA_OCSP_VR		m_stVA_OCSP_VR;
	
	VA_OCSP_VR_INIT( m_stVA_OCSP_VR );
	
	if( (m_objCert= va_read_cert_from_memory(pszAuthCert)) && (m_objIds= sk_OCSP_CERTID_new_null()) ) {
		if( (m_objName= X509_get_issuer_name( m_objCert )) ) {
			if( (m_objIssuer= X509_find_by_subject( objTrustedCAs, m_objName )) ) {
				if( va_build_ocsp_request(&m_objReq, m_objCert, m_objIssuer, m_objIds) ) {
					va_ocsp_request(m_objReq, &m_objResp, objValue );
				}
			}
		}
	}
	
	//OCSP_REQUEST_print(out, m_objReq, 0);
	//OCSP_RESPONSE_print(out, m_objResp, 0);	
	//fprintf(stdout,"STATUS=%s\n", OCSP_response_status_str( OCSP_response_status( m_objResp ) ) );
	
	//printf("Error Code: %d\n", ERR_get_error());	
	//printf("Error: %s\n", ERR_reason_error_string(ERR_get_error()));	

	if( m_objResp ) {
		m_stVA_OCSP_VR= va_ocsp_response_verify( m_objResp, m_objIds);
	}

	/*
	** Final cleanup
	*/
	if( m_objCert ) X509_free(m_objCert);
	//if( m_objIssuer ) X509_free(m_objIssuer);
	//if( m_objName ) X509_NAME_free(m_objName);
	if( m_objReq ) OCSP_REQUEST_free(m_objReq);
	if( m_objResp ) OCSP_RESPONSE_free(m_objResp);
	if( m_objIds ) sk_OCSP_CERTID_free(m_objIds);
	
	VA_OCSP_VR_SET_ERROR(m_stVA_OCSP_VR, ERR_get_error());
	return( m_stVA_OCSP_VR );
}

