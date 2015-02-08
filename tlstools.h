#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gcrypt.h> /* for gcry_control */

/* use pthread safe gcrypt */
/*GCRY_THREAD_OPTION_PTHREAD_IMPL; */


/* for gnutls 1.2 version found in sol 10 and RHEL 4, borrowed from libvirt */
#include "gnutls_1_0_compat.h"

/** The maximum length of a a fully escaped domain name C string. This
* is calculated like this: RFC1034 mandates maximum length of FQDNs
* is 255. The maximum label length is 63. Lets make it 1024 to be safe,
* after all its 2009 and bytes are cheap*/
#define MAXFQDNLEN 1024

#define TLSTOOLS_AUTH_ANON 1
#define TLSTOOLS_AUTH_X509CERT 2
#define TLSTOOLS_AUTH_PKS 3
#define TLSTOOLS_MSG_LEN 512
#define TLSTOOLS_MAX_FILE_NAME_LEN 1024 /* max file path/name len for cert files */
#define MAX_REMOTE_LOGFILE_LEN 1024 /* max len for remote log file names */

/* shared with server, and in config.h */

#define DH_BITS 1024 /* number of bits to use in DH encryption TODO: put this in the structure */

gnutls_anon_client_credentials_t tlstools_anon_cred; 
gnutls_certificate_credentials_t tlstools_x509_cred; 

/* TLS cert files*/
#define KEY_FILE "/etc/pki/slog/private/serverkey.pem"
#define CERT_FILE "/etc/pki/slog/servercert.pem"
#define CAFILE "/etc/pki/slog/CA/cacert.pem"
char *tlstools_key_file; 
char *tlstools_cert_file;
char *tlstools_ca_file; /* only requiresd on servers, or when using TLSTOOLS_AUTH_X509CERT */
char *tlstools_crl_file; /* revoked certs not implemented at the moment */
char *tlstools_client_server; /* slogd server */
int tlstools_client_serverport; /* slogd server port */
int tlstools_client_authtype; /* TLSTOOLS_AUTH_ANON or TLSTOOLS_AUTH_X509CERT */
int tlstools_client_debug;

