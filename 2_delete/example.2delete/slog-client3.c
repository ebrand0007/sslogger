#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <gnutls/gnutls.h>
#include <gcrypt.h> /* for gcry_control */
/* use pthread safe gcrypt */
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#include "tlstools.h"


/* TODO: the below gets moved to ssogger config.h ?*/
#ifndef SYSCONF_DIR
#define SYSCONF_DIR "/etc"
#endif
#define SLOGDCONF SYSCONF_DIR "/slog/slogd.conf"
#define SLOGDPIFFIE LOCAL_STATE_DIR "/run/slogd/slogd.pid"
#define  SLOG_PKI_DIR SYSCONF_DIR "/pki/slog"
#define SLOG_PKI_DIR SYSCONF_DIR "/pki/slog" 
#define SLOG_SERVKEYFILE SLOG_PKI_DIR "/private/serverkey.pem" 
#define SLOG_CERTFILE SLOG_PKI_DIR "/servercert.pem" 
#define SLOG_CAFILE SLOG_PKI_DIR "/CA/cacert.pem" 
//TODO: CRLFILE needs to be signed, so set to ""
#define SLOG_CRLFILE "" /*SLOG_PKI_DIR  "crl.pem" */



int
main (void)
{
    struct tlstools_client tlsclient;
    tlsclient.server="edslt2";
    tlsclient.port=5556;
    //tlsclient.tlstool_authtype=TLSTOOLS_AUTH_ANON;
    tlsclient.tlstool_authtype=TLSTOOLS_AUTH_X509CERT;
    tlsclient.debug=2;
   
    //tlstools_set_crl_file("/etc/funk");
    //tlstools_ca_file="/etc/slogd/fuvker";
    tlstools_cert_file="/etc/pki/slog/servercert.pem";
    tlstools_key_file="/etc/pki/slog/private/serverkey.pem";
    
    /* Initialize tls an connect to server */
    if (init_tls_client(&tlsclient)!=0) {
        fprintf(stderr,"Unable to inatalize tls conection to %s:%d\n",tlsclient.server,tlsclient.port);
        fprintf(stderr,"TLS Error:  %s\n",tlsclient.msg);
        return 1;
    }
    printf("tls initalized\n");

    int retVal=1;
    
    /* Hello string to send slogd server */
    static char *hi = "slogClient:you post\n barf\n barf choke\n";
    int sent=tlstools_send(&tlsclient,hi,strlen(hi));
    if (sent!=strlen (hi)) {
      retVal=1;
      printf("Slogd handshake e failed:%s\n",tlsclient.msg);
      //printf("TLS Hello Handshake failed: %s",gnutls_strerror(tlsclient.err));
      tlstools_end_session(&tlsclient);
      return 1;
    }
    
 /* Read the "OK" back from the server */
 char buff_ok[4]; /* Read OK back from server */
 memset (&buff_ok,0,4);
 if  (tlstools_recv(&tlsclient,buff_ok,4) < 1) { /* Error */
       printf("Error: %s\n",tlsclient.msg);
       printf("TLS connect failed: %s",gnutls_strerror(tlsclient.err));
      tlstools_end_session(&tlsclient);
      return 1;
 }
 
 /* deBUG printf("Read %s\n",buff_ok); */
 if (strcmp(buff_ok,"OK")!=0) {
   printf("Error in socket stream. Closing the connection:&s\n",tlsclient.msg);
   tlstools_end_session(&tlsclient);
   return 1;
 }
 
 /* TODO: add remender of slog-client2.c form happy hello to end */
 int i;
 for (i=0; i < 5; i++ ) {
     char msg2[40];
     sprintf(msg2,"farty boy %d\n",i);
     int sent;  
     sent=tlstools_send(&tlsclient,&msg2,strlen(msg2));
     if (sent< 0 ) {
         printf("Error: %s\n",tlsclient.msg);
         /* Terminste the tlstools session and end */
         tlstools_end_session(&tlsclient);
         return 1;
     }    
 }
 printf ("Happy session\n");
 /* tell the server we are done */
 gnutls_bye (tlsclient.session, GNUTLS_SHUT_RDWR);
 tlstools_end_session(&tlsclient); 
 return 0;
 /* end */

}

