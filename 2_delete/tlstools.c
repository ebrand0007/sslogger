#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <netdb.h>
#include <unistd.h>
#include <gnutls/gnutls.h>
#include <gcrypt.h> /* for gcry_control */
#include "tlstools.h"
/* use pthread safe gcrypt */
GCRY_THREAD_OPTION_PTHREAD_IMPL;


/* TLS helper Utility functions */

/*
    This file is part of sslogger

    sslogger is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    sslogger is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with sslogger.  If not, see <http://www.gnu.org/licenses/>.
*/




/* Mysteriously, send(2) can sometimes fail in such a way that it sends
* SIGPIPE instead of returning an error code.  This function is used as a
* replacement for send() for GNUTLS that sets the "don't signal" flag.
* This is documented in their mailing lists as an appropriate workaround.
*/
extern ssize_t
nosigpipe_push_function(gnutls_transport_ptr_t transport, const void* buf, size_t size) {
    int sd=0;  
    int *sd_ptr=transport;;
    sd=(int)sd_ptr;
    int flags = 0;
  #ifdef MSG_NOSIGNAL
    flags = MSG_NOSIGNAL;
  #endif
    int sent=send(sd, buf, size, flags);
    return sent;
}
/* TODO: above for recv */


/* Connects to the peer and returns a socket
* descriptor.
*/
extern int
tcp_connect (struct tlstools_client *tlsclient) 
{
    const char *SERVER=tlsclient->server;
    const PORT=tlsclient->port;
    int err, sd;
    struct sockaddr_in serverName = { 0 };
    struct hostent *hostPtr;// = NULL;

    if (tlsclient->debug > 0) printf ("Connecting to %s\n",SERVER);

    /* resolve the remote server name or IP address */
    hostPtr = gethostbyname(SERVER);
    if (NULL == hostPtr)
    {
        hostPtr = gethostbyaddr(SERVER,strlen(SERVER), AF_INET);
                                if (NULL == hostPtr)
                                {                                    
                                    strcpy(tlsclient->msg,"Error resolving server address");
                                    return -1;
                                }
    }
   
    memset (&serverName, '\0', sizeof (serverName));
    serverName.sin_family = AF_INET;
    serverName.sin_port = htons(PORT);
    (void) memcpy(&serverName.sin_addr,
                    hostPtr->h_addr,
                    hostPtr->h_length);

    /* connects to server */
    sd = socket(PF_INET, SOCK_STREAM,
                            IPPROTO_TCP);
                            if (-1 == sd)
                            {
                                strcpy(tlsclient->msg,"socket error");
                                return -1;
                            }
#if defined(SO_NOSIGPIPE)
    /* disable SIGPIPE signal on other OS's */
    int arg = 1;
    setsockopt(sd, SOL_SOCKET, SO_NOSIGPIPE, &arg, sizeof(int));
#endif

    err = connect (sd,  (struct sockaddr*) &serverName, sizeof (serverName));
    if (err < 0)
        {
        if (tlsclient->debug>0 )fprintf (stderr, "Connect error\n");
        return -1;
        }



    return sd;
}

/* closes the given socket descriptor.
 */
extern void
tcp_close (struct tlstools_client *tlsclient) //int sd)
{
    shutdown (tlsclient->socket_sd, SHUT_RDWR);     /* no more receptions */
    close (tlsclient->socket_sd);
}

/* end tls session and free gnutls resources 
 */
extern  void
tlstools_end_session(struct tlstools_client *tlsclient) {
    tcp_close (tlsclient);
    gnutls_deinit (tlsclient->session);
    if (tlsclient->tlstool_authtype==TLSTOOLS_AUTH_ANON)
        gnutls_anon_free_client_credentials (tlstools_anon_cred);
    if (tlsclient->tlstool_authtype==TLSTOOLS_AUTH_X509CERT)
        gnutls_certificate_free_credentials (tlstools_x509_cred);
    if (tlsclient->tlstool_authtype==TLSTOOLS_AUTH_PKS)
        gnutls_psk_free_server_credentials (tlstools_psk_cred);
    gnutls_global_deinit ();
    usleep(10000);   
}


/* initalize tlstools client
 */
extern int
init_tls_client(struct tlstools_client *tlsclient) {    
    /* Clear the msg info */
    tlsclient->msg[0]='\0';
    int retVal=-1;
    /* set defaut auth to anon if not defined */
    if (tlsclient->tlstool_authtype ==0) tlsclient->tlstool_authtype =TLSTOOLS_AUTH_ANON;
    
    /* Good to go, first initialize TLS */
    if ( initializeGnuTLS(tlsclient) < 0 ) { 
      if ( tlsclient->msg[0]=='\0') strcpy(tlsclient->msg,"Error initalizing tls");
      return -1;
    }

    /* Now Initialize the TLS session */
    tlsclient->session=initialize_tls_session (tlsclient);
    if (tlsclient->session==NULL) {
        strcpy(tlsclient->msg,"Error initalizing tls session");
        return -1;
    }

    /* connect to the peer */
    tlsclient->socket_sd = tcp_connect (tlsclient); 
    if (tlsclient->socket_sd < 0) { /* could not connect to servercert */
        sprintf(tlsclient->msg,"Error connecting to server: %s:%d\n",tlsclient->server,tlsclient->port);
        return -1;
    }
    /* set the gnutls ptr to our socket */
    gnutls_transport_set_ptr (tlsclient->session, (gnutls_transport_ptr_t) tlsclient->socket_sd);
    /* set the gnutls push function to use our send function
    *  as the gnutls function throws a SIGPIPE on error */
    gnutls_transport_set_push_function(tlsclient->session, nosigpipe_push_function);

    /* Perform the TLS handshake */
    tlsclient->err = gnutls_handshake (tlsclient->session);
    if (tlsclient->err < 0)
    {
        sprintf(tlsclient->msg,"TLS Handshake failed: %s",gnutls_strerror(tlsclient->err));
        retVal=-1;
        //goto end;
        tlstools_end_session(tlsclient);
    }
    else
    {
        if (tlsclient->debug > 0) printf("- TLS Handshake was completed\n");
    }
 
    return 0; /* happy init_tls */
    /* end init tls */  
}   

extern gnutls_session_t
initialize_tls_session (struct tlstools_client *tlsclient)
{
    /* Clear the msg info */
    //tlsclient->msg[0]='\0';

    /* GNUTLS PRIORITIES */
    /* Needed to enable anonymous KX specifically. */
    const int kx_prio[] = { GNUTLS_KX_ANON_DH, 0 };
    /* Allow connections to servers that have X509 and OpenPGP keys as well. */
    const int cert_type_priority[3] = { GNUTLS_CRT_X509,
    GNUTLS_CRT_OPENPGP, 0 };  
    
    /* below is only in tls v2.x and higher
    gnutls_priority_t priority_cache;
    uncomment the other priority_cache in this source to use */
    
    gnutls_session_t session; /* this session is retruned */
    int err;
    
    err =  gnutls_init (&session, GNUTLS_CLIENT);
    if (err != 0) goto failed;
    
    /* avoid calling all the priority functions, since the defaults
    * are adequate. */
    err = gnutls_set_default_priority (session);
    if (err != 0) goto failed;
    /* TLS v1.2 >  err = gnutls_priority_set (session, priority_cache); */
       
    if (tlsclient->tlstool_authtype==TLSTOOLS_AUTH_X509CERT ) {
        err = gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, tlstools_x509_cred);
        if (err != 0) goto failed;
    }
    
    /* TLS Anon Session Setup */
    if (tlsclient->tlstool_authtype==TLSTOOLS_AUTH_ANON ) { 
        err=gnutls_kx_set_priority (session, kx_prio);
        if (err != 0) goto failed;
        /* put the anonymous credentials to the current session */
        err=gnutls_credentials_set (session, GNUTLS_CRD_ANON, tlstools_anon_cred);
        if (err != 0) goto failed;
    }
    
    /* TLS cert session setup */
    if (tlsclient->tlstool_authtype==TLSTOOLS_AUTH_X509CERT ) {
        /* request client certificate if any.
        below needed on the server only*/
        /* gnutls_certificate_server_set_request (session, GNUTLS_CERT_REQUEST); */
        
        /* set priority to cert type */
        err=gnutls_certificate_type_set_priority (session, cert_type_priority);
        if (err != 0) goto failed;
        /* put the x509 credentials to the current session*/
        err=gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE,tlstools_x509_cred);  
        if (err != 0) goto failed;
    }
    
    /* TODO: PKS session priority & session setup is broken */
    if (tlsclient->tlstool_authtype==TLSTOOLS_AUTH_PKS) {
        err = gnutls_credentials_set (session, GNUTLS_CRD_PSK, tlstools_psk_cred);
        if (err != 0) goto failed;
    }
    
    /* set the number of bits, for use in an Diffie Hellman key exchange
    Reuquired on server only. If set on client, client will fail handshale if client-DH_BITS > server-DH_BITS 
    */
    if (tlsclient->dh_bits==0) tlsclient->dh_bits=DH_BITS; /* set default dh_bits */
    gnutls_dh_set_prime_bits (session,tlsclient->dh_bits);  
    
    return session;
    
    
    failed:
    sprintf(tlsclient->msg,"remoteInitializeTLSSession: %s", gnutls_strerror (err));
    return NULL;
    
}

extern int
initializeGnuTLS (struct tlstools_client *tlsclient)
{
    /* Clear the msg info */
    tlsclient->msg[0]='\0';
    int err;
    /* Version check should be the very first call because it
    *  makes sure that important subsystems are intialized. */
    if (!gcry_check_version (GCRYPT_VERSION))
        {
           fputs ("libgcrypt version mismatch\n", stderr);
           return -1;
         }


    /* to disallow usage of the blocking /dev/random  */
    gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
    /* tell libcrypt we are using pthread calls */
    gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
    /* Tell Libgcrypt that initialization has completed. */
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
    if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P))
    {
        strcpy(tlsclient->msg,"Error: libgcrypt has not been initialized");
        return -1;
    }

    /* Initialise GnuTLS. */
    gnutls_global_init ();
    /* set debug level */
    gnutls_global_set_log_level (tlsclient->debug);
           
    if (tlsclient->tlstool_authtype==TLSTOOLS_AUTH_X509CERT) {    
        /* verify tlstools_cert_file, tlstools_key_file, tlstools_ca_file are not null */
        if ( tlstools_cert_file[0]=='\0' || tlstools_key_file[0]=='\0'  ) {
          sprintf(tlsclient->msg,"tlstools_cert_file,  and tlstools_key_file are required for x509 certs");
          return -1;
        }
        err = gnutls_certificate_allocate_credentials (&tlstools_x509_cred);
        if (err) {
            sprintf(tlsclient->msg,"gnutls_certificate_allocate_credentials: %s",
                     gnutls_strerror (err));
                     return -1;
        }
        
        /* Set CA certificate */
        if (tlstools_ca_file && tlstools_ca_file[0] != '\0') {
            if (checkFile("CA certificate", tlstools_ca_file,tlsclient) < 0) 
                return -1;
            if (tlsclient->debug > 0) 
                sprintf(tlsclient->msg,"loading CA cert from %s", tlstools_ca_file); 
            err = gnutls_certificate_set_x509_trust_file (tlstools_x509_cred, tlstools_ca_file,
                                                          GNUTLS_X509_FMT_PEM);
                if (err < 0) {
                    sprintf(tlsclient->msg,"gnutls_certificate_set_x509_trust_file: %s",
                    gnutls_strerror (err));
                    return -1;
                }
        }
        
        /* set CRLFILE: revocation list, only needed in tls servers */         
        /*
        if (tlstools_crl_file && tlstools_crl_file[0] != '\0') {
            if (checkFile("CA revocation list", tlstools_crl_file) < 0) {
                strcpy(tlsclient->msg,,"gnutls_certificate is revoked: %s",
                return -1;
            }
            if (debug > 0) 
                strcpy(tlsclient->msg,"loading CRL from %s", tlstools_crl_file); 
            err = gnutls_certificate_set_x509_crl_file (x509_cred, crl_file,
            GNUTLS_X509_FMT_PEM);
            if (err < 0) {
                strcpy(tlsclient->msg,,"gnutls_certificate_set_x509_crl_file: %s",
                gnutls_strerror (err));
                return -1;
            }
    }
    */
        
        /* Set TLS cert_file and private key_file  */
        if (tlstools_cert_file  && tlstools_cert_file[0] != '\0' && tlstools_key_file && tlstools_key_file[0] != '\0') {
            if (checkFile("server certificate", tlstools_cert_file ,tlsclient) < 0)
                return -1;
            if (checkFile("server key", tlstools_key_file,tlsclient) < 0)
                return -1;
            if (tlsclient->debug > 1) { 
                printf("loading cert from: %s\n",tlstools_cert_file );
                printf("loading Key from: %s\n",  tlstools_key_file);
            }
            err =
            gnutls_certificate_set_x509_key_file (tlstools_x509_cred,
                    tlstools_cert_file ,tlstools_key_file,GNUTLS_X509_FMT_PEM);
            if (err < 0) {
                printf("gnutls_certificate_set_x509_key_file: %s\n",
                         gnutls_strerror (err));
                         return -1;
            }
            
        }
    } /* end if use_tls_cert */
    
    if (tlsclient->tlstool_authtype==TLSTOOLS_AUTH_ANON) {
        /* Anon Cred stuff */
        if (tlsclient->debug>1) 
            printf("Using TLS anon authentication\n");
        gnutls_anon_allocate_client_credentials (&tlstools_anon_cred);
    }
    
    if (tlsclient->tlstool_authtype==TLSTOOLS_AUTH_PKS) {
        if (tlsclient->debug>1) 
            printf("Using TLS pks authentication\n");
        err=gnutls_psk_allocate_server_credentials ((gnutls_psk_server_credentials_t*)tlstools_psk_cred);
        
        
        gnutls_psk_set_server_credentials_function (tlstools_psk_cred, pskfunc);
        //err=gnutls_psk_set_server_credentials_file(psk_cred, "pks.passwd"); //TODO: use macro
        if (err < 0) {
            printf("gnutls_psk_set_server_credentials_file: %s\n",
                     gnutls_strerror (err));
                     /*TODO: log this */
                     return -1;
        }
    }
    /* generate_dh_params only required on the server
    /*if ( generate_dh_params() < 0) {
    strcpy(tlsclient->msg,"Error: could not initalize Diffie Hellman parameters: %s",gnutls_strerror (err));
    return -1;
}*/

    return 0;
} 

//TODO: why doesnt this work with rhel5 tls?
extern int
pskfunc (gnutls_session_t session, const char *username, gnutls_datum_t * key) // TODO: these should be part of? tlstools_client struct
{
    /* Clear the msg info */
    //tlsclient->msg[0]='\0';
    printf("psk: username %s\n", username);
    key->data = gnutls_malloc (4);
    key->data[0] = 0xDE;
    key->data[1] = 0xAD;
    key->data[2] = 0xBE;
    key->data[3] = 0xEF;
    key->size = 4;
    return 0;
}


/* This function checks read access on a file
*/
extern int
checkFile(const char *type, const char *file, struct tlstools_client *tlsclient)
{
    struct stat sb;
    if (stat(file, &sb) < 0) {
        char ebuf[1024];
        sprintf(tlsclient->msg,"Cannot access %s: '%s'\n",
                 type, file );
                 return -1;
    }
    return 0;
}


/* This function sends a message to the tls server
*  Returns number of bytes sent on success
*  Returns -1 on falure
*/
int
tlstools_send(struct tlstools_client *tlsclient, void *msg,int msglen) {
  /* Clear the msg info */
  tlsclient->msg[0]='\0';
  int retVal=-1;
  retVal=gnutls_record_send (tlsclient->session, msg,msglen);
  tlsclient->err=retVal;
  check_alert(tlsclient->session,retVal);
  if (retVal == 0)
  {
    if (tlsclient->debug > 1) 
      fprintf(stderr,"Peer has closed the GNUTLS connection\n");
    sprintf(tlsclient->msg,"Peer has closed the GNUTLS connection: %s",gnutls_strerror(retVal));
    return -1;
  }
  else if (retVal < 0)
  {   
    if (tlsclient->debug>1) 
      fprintf(stderr,"*** Received unexpected/corrupted data(%d). Closing the connection. %s\n", retVal,gnutls_strerror (retVal));
    sprintf(tlsclient->msg,"Received unexpected/corrupted data. Closing the connection: %s",gnutls_strerror(retVal));
    return -1;
  }
  
  /* Verify all bytes were sent */
  if ( (retVal)!=msglen) {
    if (tlsclient->debug>1)
      fprintf(stderr,"Error: tls send failure: %s\n",gnutls_strerror(retVal));
    sprintf(tlsclient->msg,"Error: tls send failure: %s",gnutls_strerror(retVal));
    return -1;
  }    
  
  return retVal;
}


/* This function recieves a message to the session
*  Returns number of bytes sent on success
*  Returns <1 on falure
*/
int 
tlstools_recv (struct tlstools_client *tlsclient, void *msg,int msglen) {
    /* Clear the msg info */
    tlsclient->msg[0]='\0';
    tlsclient->err=gnutls_record_recv(tlsclient->session, msg,msglen);
    
    if (tlsclient->err == 0)
    {
        if (tlsclient->debug > 1) 
            fprintf(stderr,"Peer has closed the GNUTLS connection\n",gnutls_strerror(tlsclient->err));
        sprintf(tlsclient->msg,"Peer has closed the GNUTLS connection");
        tlstools_end_session(tlsclient); 
        return 0;
    }
    else if (tlsclient->err < 0)
    {   
        if (tlsclient->debug>1) 
            fprintf(stderr,"Error: Received corrupted data(%s). Closing the connection\n",gnutls_strerror(tlsclient->err));
        sprintf(tlsclient->msg,"Error: Received corrupted data(%s). Closing the connection",gnutls_strerror(tlsclient->err));
        tlstools_end_session(tlsclient); 
        return -1;
    }
    if (tlsclient->debug >1 )
        printf("Read %s\n",msg);
    return  tlsclient->err; /* return num of bytes recieved */
}

/* This function will check whether the given return code from
* a gnutls function (recv/send), is an alert, and will print
* that alert.
*/
void
check_alert (gnutls_session_t session, int ret)
{
    int last_alert;
    if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED
        || ret == GNUTLS_E_FATAL_ALERT_RECEIVED)
    {
        last_alert = gnutls_alert_get (session);
        /* The check for renegotiation is only useful if we are
        * a server, and we had requested a rehandshake.
        */
        if (last_alert == GNUTLS_A_NO_RENEGOTIATION &&
            ret == GNUTLS_E_WARNING_ALERT_RECEIVED)
            printf ("* Received NO_RENEGOTIATION alert. "
            "Client Does not support renegotiation.\n");
        else
            printf ("* Received alert ’%d’: %s.\n", last_alert,
                    gnutls_alert_get_name (last_alert));
    }
}


/* TODO: need to include this routine to verify certs were properly sigined if we want to verify certs
* slogd-server-fork.c::remoteCheckCertificate (gnutls_session_t session, char *fqdn) */

