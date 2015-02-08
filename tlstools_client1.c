//#include "config.h"
#include "tlstools.h"
#ifdef GCRYCTL_SET_THREAD_CBS
/* newer version of gcrypy use pthread safe gcrypt */
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif

/*TODO look at tlstools.h */
#define LINE_BUFF_LEN 128

gnutls_x509_crt_t crt;
gnutls_x509_privkey_t key;
gnutls_certificate_credentials_t xcred;
//gnutls_certificate_credentials_t tlstools_x509_cred; TODO: adopr var name for xcred
gnutls_anon_client_credentials_t tlstools_anon_cred; 


#if LIBGNUTLS_VERSION_MAJOR >= 1 
#if LIBGNUTLS_VERSION_MINOR >= 4
/* we have 1.4.x and cert call back function is supported  */
static int cert_callback (gnutls_session_t session,
			  const gnutls_datum_t * req_ca_rdn, int nreqs,
			  const gnutls_pk_algorithm_t * sign_algos,
			  int sign_algos_length, gnutls_retr_st * st);
#else
#warning ***X509 callback not support on this gnutls version, cert usage may be broken***
#warning *** reccomend gnutls >= 1.4
#endif
#else
#warning ***X509 callback not support on this gnutls version, cert usage may be broken***
#warning *** reccomend gnutls >= 1.4
#endif


/* Mysteriously, send(2) can sometimes fail in such a way that it sends
* SIGPIPE instead of returning an error code.  This function is used as a
* replacement for send() for GNUTLS that sets the "don't signal" flag.
* This is documented in their mailing lists as an appropriate workaround.
*/
extern ssize_t
nosigpipe_push_function(gnutls_transport_ptr_t transport, const void* buf, size_t size) {
    int sd=0;  
    int *sd_ptr=transport;
    sd=(int)sd_ptr;
    int flags = 0;
  #ifdef MSG_NOSIGNAL
    flags = MSG_NOSIGNAL;
  #endif
    int sent=send(sd, buf, size, flags);
    return sent;
}

/* TODO: above but for recv */

/* Helper functions to load a certificate and key
 * files into memory.
 */
static gnutls_datum 
load_file (const char *file)
{
  FILE *f;
  gnutls_datum loaded_file = { NULL, 0 };
  long filelen;
  void *ptr;

  if (!(f = fopen(file, "r"))
      || fseek(f, 0, SEEK_END) != 0
      || (filelen = ftell(f)) < 0
      || fseek(f, 0, SEEK_SET) != 0
      || !(ptr = malloc((size_t)filelen))
      || fread(ptr, 1, (size_t)filelen, f) < (size_t)filelen)
    {
      return loaded_file;
    }

  loaded_file.data = ptr;
  loaded_file.size = (unsigned int)filelen;
  return loaded_file;
}

static void unload_file(gnutls_datum data)
{
  free(data.data);
}

/* Load the certificate and the private key.
   Returns 0 on success, -1 on failure
 */
static int
load_keys (void)
{
  int ret;
  gnutls_datum_t data;

  data = load_file (CERT_FILE);
  if (data.data == NULL)
    {
      fprintf (stderr, "*** Error loading cert file: %s\n",CERT_FILE);
      return -1;
    }

  ret=gnutls_x509_crt_init (&crt);
  if (ret != 0)
    {
      fprintf (stderr, "*** Error in gnutls_x509_crt_init : %s\n",
         gnutls_strerror (ret));
      return ret;
    }

  ret = gnutls_x509_crt_import (crt, &data, GNUTLS_X509_FMT_PEM);
  if (ret < 0)
    {
      fprintf (stderr, "*** Error loading key file: %s\n",
	       gnutls_strerror (ret));
      return ret;
    }

  unload_file (data);

  data = load_file (KEY_FILE);
  if (data.data == NULL)
    {
      fprintf (stderr, "*** Error loading key file.\n");
      return -1;
    }

  ret=gnutls_x509_privkey_init (&key);
  if (ret != 0)
    {
      fprintf (stderr, "*** Error in gnutls_x509_privkey_init : %s\n",
         gnutls_strerror (ret));
      return ret;
    }
  ret = gnutls_x509_privkey_import (key, &data, GNUTLS_X509_FMT_PEM);
  if (ret < 0)
    {
      fprintf (stderr, "*** Error loading key file: %s\n",
	       gnutls_strerror (ret));
      return ret;
    }

  unload_file (data);
  return 1;
}

/* Connects to the peer and returns a socket
* descriptor.
*/
long tcp_connect (const char *SERVER, int PORT)
{
    int err;
    long sd;
    struct sockaddr_in serverName = { 0 };
    struct hostent *hostPtr;

    if (tlstools_client_debug > 0) printf ("DEBUG: connecting to %s\n",SERVER);

    /* resolve the remote server name or IP address */
    hostPtr = gethostbyname(SERVER);
    if (NULL == hostPtr)
    {
        hostPtr = gethostbyaddr(SERVER,strlen(SERVER), AF_INET);
                                if (NULL == hostPtr)
                                {                                    
                                    fprintf(stderr,"Error: in resolving server address");
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
				if (tlstools_client_debug) 
                                  fprintf(stderr,"Error: with socket");
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
        if (tlstools_client_debug>0 )fprintf (stderr, "Error: in connect \n");
        return -1;
        }



    return sd;
}

/* closes the given socket descriptor.
 */
int
tcp_close (long sd)
{
    int ret;
    ret = shutdown (sd, SHUT_RDWR);     /* no more receptions */
    close (sd);
    return ret;
}

/* This function sends a message to the tls server
*  Returns number of bytes sent on success
*  Returns bytes sent, -1 on falure, 0 on peer closed connection
*/
int
tlstools_send(gnutls_session_t session, char *msg,int msglen) {
  /* Clear the msg info */
  int retVal=-1;
  retVal=gnutls_record_send (session, msg,msglen);
  
  if (retVal == 0)
  {
    if (tlstools_client_debug > 1)
      fprintf(stderr,"Peer has closed the GNUTLS connection\n");
    return 0;
  }
  else if (retVal < 0)
  {
    if (tlstools_client_debug>1)
      fprintf(stderr,"*** Received unexpected/corrupted data(%d). Closing the tls connection. %s\n", retVal,gnutls_strerror (retVal));
    return -1;
  }
  
  /* Verify all bytes were sent */
  if ( (retVal)!=msglen) {
    if (tlstools_client_debug>1)
      fprintf(stderr,"Error: tls send failure: %s\n",gnutls_strerror(retVal));
    return -1;
  }
  
  return retVal;
}



/* This function recieves a message to the session
*  Returns number of bytes sent on success
*  Returns bytes sent. 0 peer closed connection, <0 on error
*/
int
tlstools_recv (gnutls_session session,char *msg,int msglen) {
  msg[0]='\0';
  int err=gnutls_record_recv(session, msg,msglen-1);
  if (err == 0)
  {
    if (tlstools_client_debug > 1)
      fprintf(stderr,"Peer has closed the GNUTLS connection\n",gnutls_strerror(err));
    return 0;
  }
  else if (err < 0)
  {
    if (tlstools_client_debug>1)
      fprintf(stderr,"Error: Received corrupted data(%s). Closing the connection\n",gnutls_strerror(err)); 
    return -1;
  }
  if (tlstools_client_debug >1 )
    printf("DEBUG: Read %s\n",msg);
  return  err; /* return num of bytes recieved */
}

int tlstools_end_session(long socket_sd,gnutls_session_t session) {
    tcp_close (socket_sd);
    gnutls_deinit (session);

    if (tlstools_client_authtype==TLSTOOLS_AUTH_X509CERT)
        gnutls_certificate_free_credentials (xcred);
    if (tlstools_client_authtype==TLSTOOLS_AUTH_ANON)
        gnutls_anon_free_client_credentials (tlstools_anon_cred);

    gnutls_global_deinit ();
    return 0;
}

/* init a gnutls x509 session 
   returns NULL on error
*/
gnutls_session_t 
tlstools_init_xcred (void) {
    /* x509 specfic */
    int err;
    gnutls_session_t session; /* this is returned */
    
    /* load x509 keys/certs */
    if (load_keys () <1) 
        return NULL; 
    
    /* X509 stuff */
    err=gnutls_certificate_allocate_credentials (&xcred);
    if (err!=0) { 
        fprintf(stderr,"Error: gnutls_certificate_allocate_credentials: %s\n",
                gnutls_strerror (err));
                return NULL;
    }
    
    /* sets the trusted ca file
    */
    err=gnutls_certificate_set_x509_trust_file (xcred, CAFILE, GNUTLS_X509_FMT_PEM);
    if (err < 0) {
      fprintf(stderr,"Error: in gnutls_certificate_set_x509_trust_file: %s\n",
      gnutls_strerror (err));
      return NULL;
    }

#if LIBGNUTLS_VERSION_MAJOR >= 1 
#if LIBGNUTLS_VERSION_MINOR >= 4
/* we have 1.4.x and cert call back function is supported */
    gnutls_certificate_client_set_retrieve_function (xcred, cert_callback);
#endif
#endif
    /* Initialize TLS session 
    */
    err=gnutls_init (&session, GNUTLS_CLIENT);
    if (err != 0) {
      fprintf(stderr,"Error: in gnutls_init: %s\n",
      gnutls_strerror (err));
      return NULL;
    }

    
    /* Use default priorities */
    err=gnutls_set_default_priority (session);
    if (err != 0) {
      fprintf(stderr,"Error: in  gnutls_set_default_priority\n");
      return NULL;
    }


    /* put the x509 credentials to the current session
    */
    err=gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, xcred);
    if (err != 0) { 
        fprintf(stderr,"Error: in x509 gnutls_credentials_set\n");
        return NULL;
    }
        
    return session;
}

/* init a gnutls anon session 
   returns NULL on error
*/
gnutls_session_t
tlstools_init_anon(void) {
  gnutls_session_t session;
  int err;

  /* TODO: does below need to be defined globally? */
  /* Need to enable anonymous KX specifically. */
  const int kx_prio[] = { GNUTLS_KX_ANON_DH, 0 };



  err=gnutls_anon_allocate_client_credentials (&tlstools_anon_cred);
  if (err<0) {
    fprintf(stderr,"Error: in rgnutls_certificate_allocate_credentials: %s\n",
      gnutls_strerror (err));
    return NULL;
  }
  
/* Initialize TLS session
 *    */
  err=gnutls_init (&session, GNUTLS_CLIENT);
  if (err != 0) {
    fprintf(stderr,"Error: in gnutls_init: %s\n",
      gnutls_strerror (err));
    return NULL;
  }

  /* Use default priorities */
  err=gnutls_set_default_priority (session);
  if (err != 0) {
    fprintf(stderr,"Error: in  gnutls_set_default_priority\n"); 
  return NULL;
  }

  err=gnutls_kx_set_priority (session, kx_prio);
  if (err != 0) {
    fprintf(stderr,"Error: gnutls_kx_set_priority: %s\n",
      gnutls_strerror (err));
    return NULL;
  }
  /* put the anonymous credentials to the current session
 *    */
  gnutls_credentials_set (session, GNUTLS_CRD_ANON, tlstools_anon_cred);
  if (err != 0) {
    fprintf(stderr,"Error: in setting anon gnutls_credentials_set\n");
    return NULL;
  }


 return session;
}

/* Send our handshake to server, sets remote_logfile and
Returns <0 on tcpconnect error, -1 on handshake err
*/
int
tlstools_connect (char *server,int port,long socket_sd,gnutls_session_t session,char **msg, char *remote_logfile,int remote_logfile_len)
    {
    int ret, ii;
    char line[MAX_REMOTE_LOGFILE_LEN];
    memset (&line, '\0', sizeof (line));
    /* connect to the peer
    */
    socket_sd = tcp_connect (server,port);
    if (socket_sd < 0) {
        fprintf(stderr,"Error: failed to connect to %s:%d\n",server,port);
        return 0;
    }
   
    if (tlstools_client_debug>0) {
        printf ("DEBUG: connected\n");
        if (session==NULL) printf ("DEBUG: session is null");
    }
    /* set the gnutls ptr to our socket */
    gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t)socket_sd);
    
    /* Perform the TLS handshake:
    */
    ret = gnutls_handshake (session);
    if (ret < 0)
    {
        fprintf (stderr, "*** Gnutls handshake failed\n");
        gnutls_perror (ret);
        return -1;
    }
    else
    {
        if (tlstools_client_debug>0)
            printf ("DEBUG: Gnutls handshake was completed\n");
    }
    
    /* Send our Hello */
    int msg_len=strlen((char*)msg);
    ret=tlstools_send(session,(char*)msg,msg_len);
    if (ret == 0)
    {
        fprintf (stderr,"Error: Peer has closed the TLS connection\n");
        return -1;
    }
    else if (ret < 0)
    {
        fprintf (stderr, "*** Error: %s\n", gnutls_strerror (ret));
        return -1;
    }
    
    
    /* Read Responce back from slogd server */
    /* Responce will contain OK followed by slogd log file */
    ret=tlstools_recv(session, line, MAX_REMOTE_LOGFILE_LEN); /* line will always be null terminated */
    if (ret == 0)
    {
        fprintf (stderr,"Error: Peer has closed the TLS connection\n");
        return -1;
    }
    else if (ret < 0)
    {
        fprintf (stderr, "*** Error: %s\n", gnutls_strerror (ret));
        return -1;
    }


    
    if (tlstools_client_debug >1 ) {
        printf ("DEBUG: Received %d bytes: ", ret);
        for (ii = 0; ii < ret; ii++)
        {
            fputc (line[ii], stdout);
        }
        fputs ("\n", stdout);
    }
    
    /* Make sure we get  logfile: or OK from the server */
    if (strncmp(line,"logfile:",8)==0) {
      char *offset;
      offset=&line[8];
      /* and set remote_logfile */
      strcpy(remote_logfile,offset); 
    }
    else if (strncmp(line,"OK",2)==0) {
    }
    else { /* err out */
      fprintf(stderr,"Error in gnutls socket stream. Closing the connection\n");
      return -1;
      
    }
    
    return 1;
}

/* Init GNU tls Session */
gnutls_session_t
tlstools_init (void) {
  gnutls_session_t session;
#ifdef GCRYCTL_SET_THREAD_CBS
  /* added below to fix thread isssue on solaris with gcrypt */
  gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
#endif
  gnutls_global_init ();
  
  if (tlstools_client_authtype==TLSTOOLS_AUTH_X509CERT ) {
    if (tlstools_client_debug > 0) 
        printf ("DEBUG: using x509 tls auth\n");
    session=tlstools_init_xcred();
    if (session==NULL) {
        fprintf (stderr,"Error: failed to initalize x509 tls session\n");
        return NULL; /* err out */
    }
  }
  else if (tlstools_client_authtype==TLSTOOLS_AUTH_ANON ) {
    if (tlstools_client_debug > 0)
        printf ("DEBUG: using anon tls auth\n");
      session=tlstools_init_anon();
    if (session==NULL) {
        fprintf (stderr,"Error: failed to initalize anon tls session\n");
        return NULL; /* err out */
    }
  }
  else {
      fprintf(stderr,"Error: tlstools_client_authtype is not set\n");
      return NULL;
  }

#ifdef __linux__
  /* set the gnutls push function to use our send function
  *  as the gnutls function throws a SIGPIPE on error */
  gnutls_transport_set_push_function(session, nosigpipe_push_function);
#endif

  return session;
}

#if LIBGNUTLS_VERSION_MAJOR >= 1 
#if LIBGNUTLS_VERSION_MINOR >= 4
/* This callback should be associated with a session by calling
 * gnutls_certificate_client_set_retrieve_function( session, cert_callback),
 * before a handshake.
 */
static int
cert_callback (gnutls_session_t session,
	       const gnutls_datum_t * req_ca_rdn, int nreqs,
	       const gnutls_pk_algorithm_t * sign_algos,
	       int sign_algos_length, gnutls_retr_st * st)
{
  char issuer_dn[256];
  int i, ret;
  size_t len;
  gnutls_certificate_type_t type;


  if (tlstools_client_debug>0) {
    /* Print the server's trusted CAs
    */
    if (nreqs > 0)
      printf ("DEBUG: Server's trusted authorities:\n");
    else
      printf ("DEBUG: Server did not send us any trusted authorities names.\n");
      /* TODO: handel this */
  
  
    
    /* print the names (if any) */
    for (i = 0; i < nreqs; i++)
    {
      len = sizeof (issuer_dn);
      ret = gnutls_x509_rdn_get (&req_ca_rdn[i], issuer_dn, &len);
      if (ret >= 0)
      {
      printf ("DEBUG:   [%d]: ", i);
      printf ("%s\n", issuer_dn);
      }
    }
  }

  /* Select a certificate and return it.
   * The certificate must be of any of the "sign algorithms"
   * supported by the server.
   */
  type = gnutls_certificate_type_get (session);
  if (type == GNUTLS_CRT_X509)
    {
      st->type = type;
      st->ncerts = 1;

      st->cert.x509 = &crt;
      st->key.x509 = key;

      st->deinit_all = 0;
    }
  else
    {
      return -1;
    }

  return 0;

}
#endif
#endif


