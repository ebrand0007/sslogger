/* Copyright 2007, 2008 Free Software Foundation
 *
 * Copying and distribution of this file, with or without modification,
 * are permitted in any medium without royalty provided the copyright
 * notice and this notice are preserved.
 */

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


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <syslog.h>
#include <pthread.h>
#include <gnutls/gnutls.h>
#include <gcrypt.h> /* for gcry_control */


#ifdef GCRYCTL_SET_THREAD_CBS
/* newer version of gcrypy use pthread safe gcrypt */
/* use pthread safe gcrypt */
GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif

#include "config.h"
#include "gnutls_1_0_compat.h"

/* Mutex for syncronized global data between threads */
pthread_mutex_t global_data_mutex;

struct worker_pthread {
    pthread_t thread;
    long socket; /* client conection fd*/
    gnutls_session_t session;
    char fqdn[MAXFQDNLEN];
    int cli_port;
    long server; /* listening socket fd */
    //TODO: need a method to track open connections
};


/* Of the three modes below, only one can be enable at a time */
int use_tls_cert=1; /* set to 1 to use tls certs for authenitcation */
int use_tls_anon=0; /* set to 1 to use anon auth */
int use_tls_pks=0; /*set to 1 to use tls pks (TODO: untested and broken in rhel5)*/ 
static int tls_verify_certificate = 1; //set to 1 to force client cert check, but requires ca_file on client
static int tls_no_verify_host = 0; //set to 1 to enforce client hostname check TODO: implement this

static int debug=0;
static int godaemon=0;
static char *progname;
static int port=PORT;
static char *conf_file=SLOGDCONF;
static char *pid_file=SLOGDPIFFIE;

/* These are global */
volatile sig_atomic_t forever = 1; /* controls program termination */
static gnutls_certificate_credentials_t x509_cred;
static gnutls_anon_server_credentials_t anon_cred;
static gnutls_dh_params_t dh_params;
/* below is only in tls v2.x and higher
   gnutls_priority_t priority_cache;
  uncomment the other priority_cache in this source to use
*/

/* GNUTLS PRIORITIES */
/* Needed to enable anonymous KX specifically. */
const int kx_prio[] = { GNUTLS_KX_ANON_DH, 0 };

static char *key_file = (char *) SLOG_SERVKEYFILE; //KEYFILE
static char *cert_file = (char *) SLOG_CERTFILE; //CERTFILE
static char *ca_file = (char *) SLOG_CAFILE; //CAFILE
static char *crl_file = (char *) SLOG_CRLFILE; //"" in libvirt

/* Function prototypes: */
void termination_handler (int signum); /* clean up before termination */
static int mysyslog(const char *str, int priority);


void log_info (int bufSize, char * format, ...)
{
    char buffer[bufSize];
    va_list args;
    va_start (args, format);
    vsprintf (buffer,format, args);
    //perror (buffer);
    va_end (args);
    
    if (godaemon) {
        mysyslog(buffer,LOG_INFO);
    }
    else
        printf(buffer);
}

/*
* Stop extremely silly gcc complaint on %c:
*  warning: `%c' yields only last 2 digits of year in some locales
*/
static void
my_strftime(char *buf, size_t len, const char *fmt, const struct tm *tm) {
    strftime(buf, len, fmt, tm);
}

int logCmd(char* message, const char *logfname) {
    
    FILE *log;
    log=fopen(logfname,"a");
    
    if (log == NULL ) {
        /* Can't open file */
        log_info(1024,"Error: can't open logfile: %s\n",logfname);
        return -1;
        
    }
    
    /*time format for logfname*/
    char outstr[200];
    time_t t;
    struct tm *tmp;
    t = time(NULL);
    tmp = localtime(&t);
    if (tmp == NULL) {
        log_info(1024,"Error getting localtime()\n");
        return -1;
    }
    if (strftime(outstr, sizeof(outstr), "%F %H:%M:%S", tmp) == 0) {
        log_info(1024,"strftime returned 0");
        return -1;
    } 
    
    if (debug) 
        log_info(1024,"opening log file %s\n",logfname);

    int p=getpid(); //get the pid
    /* TODO!!! Need errorchecking on fprint!!! */
    fprintf(log,"%s %s\n",outstr,message);
    if (ferror(log)) {
        log_info(1024,"Error writing to %s:%s\n",logfname,strerror(errno));
        if (log!=NULL) fclose(log);
        return -1;
        
    }
    /* above format changed, see sslogger.c::logCmd2 for original format */
    fclose(log);
    
    return 0; //happy ending
}

static gnutls_session_t
initialize_tls_session (void)
{
  char *message;
  gnutls_session_t session;
  int err;

  err =  gnutls_init (&session, GNUTLS_SERVER);
  if (err != 0) goto failed;
  
  /* avoid calling all the priority functions, since the defaults
  * are adequate.
  */
  err = gnutls_set_default_priority (session);
  /* TLS v1.2 >  err = gnutls_priority_set (session, priority_cache); */
  if (err != 0) goto failed;
  
  if ((use_tls_cert==1) || (use_tls_pks==1)) {
    err = gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);
    if (err != 0) goto failed;
  }
  
  /* anon auth */
  if (use_tls_anon==1)  {
      err = gnutls_kx_set_priority (session, kx_prio);
      if (err != 0) goto failed;
      err = gnutls_credentials_set (session, GNUTLS_CRD_ANON, anon_cred);
      if (err != 0) goto failed;
  }

  /* request client certificate if any.
   */
  if ((use_tls_cert == 1) || (use_tls_pks == 1) ) { 
      /* Require client Cert */
      gnutls_certificate_server_set_request (session, GNUTLS_CERT_REQUEST);
  }
  /* We dont need the below, as we are using anon auth
  else {
    //Anon auth, or server using  CA but not client
    gnutls_certificate_server_set_request (session, GNUTLS_CERT_IGNORE);
  }
  */
  
  gnutls_dh_set_prime_bits (session, DH_BITS);
  return session;
  
  failed:
    log_info(1000,"remoteInitializeTLSSession: %s\n", gnutls_strerror (err));
    return NULL;
  
}

static int
remoteCheckCertificate (gnutls_session_t session, char *fqdn)
{
  /* TODO: when we rewrite the client, we need to include this rutine to verify certs were properly sigined. */
  int ret;
  unsigned int status;
  const gnutls_datum_t *certs;
  unsigned int nCerts, i;
  time_t now;
  
  #if LIBGNUTLS_VERSION_MAJOR  >=1
  /* gnults 1.x uses gnutls_certificate_verify_peers2 */
  if ((ret = gnutls_certificate_verify_peers2 (session, &status)) < 0){
    log_info(1000,"%s remoteCheckCertificate: verify failed: %s\n",fqdn,
                gnutls_strerror (ret));
                return -1;
  }
  #else
  status=gnutls_certificate_verify_peers(session);
  #endif
  

  if (status != 0) {
    log_info(1000,"remoteCheckCertificate: "
       "%s failed certificate security check\n",fqdn);

    if (status & GNUTLS_CERT_INVALID)
      log_info(1000,"remoteCheckCertificate: "
      "the client certificate is not trusted.\n");

    #ifdef GNUTLS_CERT_SIGNER_NOT_FOUND    
    if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
      log_info(1000,"remoteCheckCertificate: the client "
      "certificate has unknown issuer.\n");
    #endif

    if (status & GNUTLS_CERT_REVOKED)
      log_info(1000,"remoteCheckCertificate: "
      "the client certificate has been revoked.\n");


    #ifndef GNUTLS_1_0_COMPAT
    if (status & GNUTLS_CERT_INSECURE_ALGORITHM)
      log_info(1000,"remoteCheckCertificate: the client certificate"
      " uses an insecure algorithm.\n");
    #endif
    
    return -1;
  }
  
  if (gnutls_certificate_type_get (session) != GNUTLS_CRT_X509) {
    log_info(1000,"remoteCheckCertificate: certificate is not X.509\n");
    return -1;
  }
  
  if (!(certs = gnutls_certificate_get_peers(session, &nCerts))) {
    log_info(1000,"remoteCheckCertificate: no peers\n");
    return -1;
  }
  
  now = time (NULL);
  
  /* loop through all the client certs, first the peers, then the issuers, then the isuer's issure */
  for (i = 0; i < nCerts; i++) {
    gnutls_x509_crt_t cert;
    
    if (gnutls_x509_crt_init (&cert) < 0) {
      log_info(1000,"remoteCheckCertificate: gnutls_x509_crt_init failed\n");
      return -1;
    }
    
    if (gnutls_x509_crt_import(cert, &certs[i], GNUTLS_X509_FMT_DER) < 0) {
      gnutls_x509_crt_deinit (cert);
      return -1;
    }
    
    if (gnutls_x509_crt_get_expiration_time (cert) < now) {
      //TODO: allow flag to use expired certs
      log_info(1000,"remoteCheckCertificate: "
      "the client certificate has expired\n");
      gnutls_x509_crt_deinit (cert);
      return -1;
    }
    
    if (gnutls_x509_crt_get_activation_time (cert) > now) {
        log_info(1000,"remoteCheckCertificate: the client "
        "certificate is not yet activated\n");
        gnutls_x509_crt_deinit (cert);
        return -1;
    }
    
    /* see gnutls_certificate_verify_peers2 */
    if (i == 0) { //No certs were found, so chech   
        char name[MAXFQDNLEN];
        size_t namesize = sizeof name;
        int err;
        
        err = gnutls_x509_crt_get_dn (cert, name, &namesize);
        /* Verify peer DN matched ours */
        if (err!=0) {
            log_info(1000,"Error: remoteCheckCertificate::gnutls_x509_crt_get_dn error\n");
            /* see libvirt::remoteCheckDN  whitlist???\n see also: gnutls_certificate_get_peers"); */
            return -1;
        }
      }
    }
  
  return 0;
}

static int
generate_dh_params (void)
{

  /* Generate Diffie Hellman parameters - for use with DHE
   * kx algorithms. When short bit length is used, it might
   * be wise to regenerate parameters once a day, 
   * once a week or once a month. Depending on the
   * security requirements.
   *
   */
  int err;
  err = gnutls_dh_params_init (&dh_params);
  if (err < 0) {
      log_info(1000,"gnutls_dh_params_init: %s", gnutls_strerror (err));
      return -1;
  }
  err = gnutls_dh_params_generate2 (dh_params, DH_BITS);
  if (err < 0) {
      log_info(1000,"gnutls_dh_params_generate2: %s", gnutls_strerror (err));
      return -1;
  };
  if ((use_tls_cert==1 ) || (use_tls_pks==1)) 
    gnutls_certificate_set_dh_params (x509_cred, dh_params);
  if (use_tls_anon==1)
    gnutls_anon_set_server_dh_params (anon_cred, dh_params);
  return 0;
}


static int mysyslog ( const char *str, int priority ) {
    int prio;
    switch (priority) {
        case LOG_DEBUG:
            prio = LOG_DEBUG;
            break;
        case LOG_INFO:
            prio = LOG_INFO;
            break;
        case LOG_WARNING:
            prio = LOG_WARNING;
            break;
        case LOG_ERR:
            prio = LOG_ERR;
            break;
        default:
            prio = LOG_ERR;
    }
        syslog(prio, "%s", str);
    return 0;
}

static int goDaemon(void) {
    int pid = fork();
    switch (pid) {
        case 0:
        {
            int stdinfd = -1;
            int stdoutfd = -1;
            int nextpid;
            
            if ((stdinfd = open("/dev/null", O_RDONLY)) < 0)
                goto cleanup;
            if ((stdoutfd = open("/dev/null", O_WRONLY)) < 0)
                goto cleanup;
            if (dup2(stdinfd, STDIN_FILENO) != STDIN_FILENO)
                goto cleanup;
            if (dup2(stdoutfd, STDOUT_FILENO) != STDOUT_FILENO)
                goto cleanup;
            if (dup2(stdoutfd, STDERR_FILENO) != STDERR_FILENO)
                goto cleanup;
            if (close(stdinfd) < 0)
                goto cleanup;
            stdinfd = -1;
            if (close(stdoutfd) < 0)
                goto cleanup;
            stdoutfd = -1;
            
            if (setsid() < 0)
                goto cleanup;
            
            nextpid = fork();
            switch (nextpid) {
                case 0:
                    log_info(1024,"Setting signals\n");
                    /* child */
                    
                    /* Establish signal handler to clean up before termination: */
                    /*if (signal (SIGINT, termination_handler) == SIG_IGN)
                        signal (SIGINT, SIG_IGN); */
                    /* TODO add a sighup haneler, currently stops server from listening */
                    /*if (signal (SIGHUP, termination_handler) == SIG_IGN)
                        signal (SIGHUP, SIG_IGN); */
                    signal(SIGHUP, termination_handler);
                    if (signal (SIGTERM, termination_handler) == SIG_IGN)
                        signal (SIGTERM, SIG_IGN);
                    if (signal (SIGQUIT, termination_handler) == SIG_IGN)
                        signal (SIGQUIT, SIG_IGN);   
                    signal(SIGCHLD,termination_handler); /* TODO: test Ignore signals from my children to prevent zobies */
                    return 0;
                case -1:
                    /* error forking */
                    return -1;
                default:
                    /* parent */
                    _exit(0);
            }
            
            cleanup:
            if (stdoutfd != -1)
                close(stdoutfd);
            if (stdinfd != -1)
                close(stdinfd);
            return -1;
            
        }
        
                case -1:
                    return -1;
                    
                default:
                {
                    int got, status = 0;
                    /* We wait to make sure the next child forked
                    successfully */
                    if ((got = waitpid(pid, &status, 0)) < 0 ||
                        got != pid ||
                        status != 0) {
                        return -1;
                    }
                    _exit(0);
                }
    }
}

static int
checkFile(const char *type, const char *file)
{
    struct stat sb;
    if (stat(file, &sb) < 0) {
        log_info(1000,"Cannot access %s: '%s'\n",
            type, file );
                return -1;
    }
    return 0;
}

static int
initializeGnuTLS (void)
{
    int err;

    #ifdef GCRYCTL_ENABLE_QUICK_RANDOM
    /* to disallow usage of the blocking /dev/random  */
    gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
    #endif

    #ifdef GCRYCTL_SET_THREAD_CBS
    /* tell libcrypt we are using pthread calls */
    gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
    #endif
    /* Tell Libgcrypt that initialization has completed. */
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
    if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P))
    {
        log_info(1000,"Error: libgcrypt has not been initialized\n");
       return -1;
    }
    
    /* Initialise GnuTLS. */
    gnutls_global_init ();

    /* set debug level */
    gnutls_global_set_log_level (debug); 
  
  /* using tls_x590_auth */  
    if ( (use_tls_pks == 1) || (use_tls_cert ==1 ) ) { 
        err = gnutls_certificate_allocate_credentials (&x509_cred);
        if (err) {
            log_info(1000,"gnutls_certificate_allocate_credentials: %s\n",
                    gnutls_strerror (err));
                    return -1;
        }
    
        /* SLOG_CAFILE: CA certificate */
        if (ca_file && ca_file[0] != '\0') {
            if (checkFile("CA certificate", ca_file) < 0) 
                return -1;
            if (debug > 0) 
                log_info(1000,"loading CA cert from %s\n", ca_file); 
            err = gnutls_certificate_set_x509_trust_file (x509_cred, ca_file,
                GNUTLS_X509_FMT_PEM);
            if (err < 0) {
                log_info(1000,"gnutls_certificate_set_x509_trust_file: %s\n",
                gnutls_strerror (err));
            return -1;
            }
        }
    
        /* SLOG_CRLFILE: revocation list */         
        if (crl_file && crl_file[0] != '\0') {
            if (checkFile("CA revocation list", crl_file) < 0)
                return -1;
            
        if (debug > 0) 
            log_info(1000,"loading CRL from %s\n", crl_file); 
        err = gnutls_certificate_set_x509_crl_file (x509_cred, crl_file,
            GNUTLS_X509_FMT_PEM);
            if (err < 0) {
                log_info(1000,"gnutls_certificate_set_x509_crl_file: %s\n",
                gnutls_strerror (err));
                return -1;
            }
        }                    
        
        /* SLOG TLS servercert and key */
        if (cert_file && cert_file[0] != '\0' && key_file && key_file[0] != '\0') {
            if (checkFile("server certificate", cert_file) < 0)
            return -1;
            if (checkFile("server key", key_file) < 0)
                return -1;
            if (debug > 0) { 
                log_info(1000,"loading cert from: %s\n",cert_file);
                log_info(1000,"loading Key from: %s\n",  key_file);
            }
            err =
                gnutls_certificate_set_x509_key_file (x509_cred, cert_file, key_file,
                GNUTLS_X509_FMT_PEM);
            if (err < 0) {
                log_info(1000,"gnutls_certificate_set_x509_key_file: %s",
                gnutls_strerror (err));
                return -1;
            }
        } 

        else 
            if (debug>1) log_info(1000,"Using TLS certs authentication\n");
        
        if ( generate_dh_params() < 0) {
            log_info(1000,"Error: could not initalize Diffie Hellman parameters: %s\n",gnutls_strerror (err));
            return -1;
        }
    } /*End TODO: use certs */
 
    else if (use_tls_anon == 1) {
        if (debug>1) log_info(1000,"Using TLS anon authentication\n");
        gnutls_anon_allocate_server_credentials (&anon_cred);
        if ( generate_dh_params() < 0) {
            log_info(1000,"Error: could not initalize Diffie Hellman parameters: %s\n",gnutls_strerror (err));
            return -1;
        }  
    }
 
 
    return 0;
} 

/**
* virAlloc:
* @ptrptr: pointer to pointer for address of allocated memory
* @size: number of bytes to allocate
*
* Allocate  'size' bytes of memory. Return the address of the
* allocated memory in 'ptrptr'. The newly allocated memory is
* filled with zeros.
*
* Returns -1 on failure to allocate, zero on success
*/
int virAlloc(void *ptrptr, size_t size)
{
    *(void **)ptrptr = calloc(1, size);
    if (*(void **)ptrptr == NULL)
        return -1;
    return 0;
}

/**
* virFree:
* @ptrptr: pointer to pointer for address of memory to be freed
*
* Release the chunk of memory in the pointer pointed to by
* the 'ptrptr' variable. After release, 'ptrptr' will be
* updated to point to NULL.
*/

void virFree(void *ptrptr)
{
    free(*(void**)ptrptr);
    *(void**)ptrptr = NULL;
}

static void
proccess_connection_fork(struct worker_pthread *worker) { 
    
   /* TODO: unify the below log file name from using var in slogd.conf */
   /* same for slogger.c */
   const char *logfname; /* master slogd log file */
   const char *log_dir=STRINGIFY(LOG_DIR);
   const char *log_file=STRINGIFY(SLOGFILE);
   asprintf(&logfname,"%s/%s",log_dir,log_file);
   
    char *fname; /* file name for sslogger output */
    FILE *fscript=NULL; /* FILE for ssloger output */
    if (debug > 2) 
        log_info(1000,"the memory address of worker is:%d\n",worker);
    int d=worker->socket;
    char buffer[MAX_BUF + 1];
    
    /* checkFile access for master slogd log file*/
    if (access(logfname,W_OK)==-1) {
        log_info(1024,"Cannot write to %s\n",logfname);
        goto cleanup;
    }
    
    log_info(1200,"Connection from %s port %d slogdpid %d\n",worker->fqdn,worker->cli_port,getpid());
    gnutls_transport_set_ptr (worker->session, (gnutls_transport_ptr_t)  worker->socket);
    int ret = gnutls_handshake (worker->session);
    if (ret < 0)
    {
        log_info(1000, "*** Handshake has failed (%s)\n",
                 gnutls_strerror (ret));
        goto cleanup;
    }
    
    if (debug > 0) 
        log_info(1000,"- Handshake was completed\n");
    
    if (use_tls_cert ==1 ) {
        log_info(1024,"Checking client cert\n");
        /*  Next step is to check the certificate. */
        if (remoteCheckCertificate (worker->session,worker->fqdn) == -1) {
            log_info(1000,"remoteCheckCertificate: failed to verify client's certificate: %s\n",worker->fqdn);
            if (tls_verify_certificate==1) {
                goto cleanup;    
            }
            else log_info(1000,"remoteCheckCertificate: tls_verify_certificate is not set so the bad certificate is ignored\n");
        }
    }
    
    /* read the first HEADER_LABEL_LEN bytes looking for "HEADER_LABEL" 
    * if found continue processing connection
    * if not, exit processThread. Note: See config.h for sslogger HEADER_LABEL equilivant
    */
    
    char header[HEADER_LABEL_LEN+1]; 
    memset (header, 0,HEADER_LABEL_LEN+1 ); 
    ret = gnutls_record_recv (worker->session, header, HEADER_LABEL_LEN);
    if (ret == 0)
    {
        if (debug > 1) 
            log_info (1000,"Peer has closed the GNUTLS connection\n");
        goto cleanup;
    }
    else if (ret < 0)
    {   
        if (debug>1) 
            log_info(1000, "*** Received unexpected/corrupted data(%d). Closing the connection. %s\n", ret,gnutls_strerror (ret));
        goto cleanup;
    }
    
    header[HEADER_LABEL_LEN+1]='\0';
    const char *header_label=STRINGIFY(HEADER_LABEL); 
    if (strcmp(header,header_label)!=0) {
        /* THIS IS NOT A Valid slog header */
        if (debug>2) 
            log_info(1024,"Malformed sslogger client header:%s from:%s\n",header,worker->fqdn);
        goto cleanup;
    }
    if (debug>2)
        log_info(1024,"Client connection accepted: %s\n",worker->fqdn);
    
    
    /* now read remainig 1024 header bytes and write to master to log file */
    int i=0;
    char ch='\0';
    
    /* TODO PUT MAX_HEADER_LEN in config.h .. same as max_comment_len? in sslogger */
    char logString[MAX_HEADER_LEN];
    while (i < MAX_HEADER_LEN ) {
        ret=gnutls_record_recv (worker->session, &ch, 1);
        if (ret == 0)
        {
            if (debug > 1) 
                log_info (1000,"Peer has closed the GNUTLS connection\n");
            goto cleanup;
        }
        else if (ret < 0)
        {   
            if (debug>1) 
                log_info(1000, "*** Received corrupted data while processing data (%s). Closing the connection\n", gnutls_strerror (ret));
            goto cleanup;
        }
        if (ch == '\n' ) {
            if (debug>1) printf("slogd: client read EOL\n");
            break; /* found end of line */
        }
        /* ad ch to logString */
        logString[i]=ch;
        i++; /* successful read of a char */
    }
    logString[i]='\0'; /* terminate string */
    if (debug>2)
        log_info(2000,"Writing string to log:\n %s\n",logString);
 
        /* Log FileName formatting: fname is the file name to log output to */
        time_t tvec;
        tvec = time((time_t *)NULL);
        // create and use LOG_DIR/sl/<year>/<month>/$logfile-$fqdn-$date.log
        char year[6];
        char month[3];
        char day[3];
        char time[30];
        long millisec;
        char ldate[60]; /* Enough to hols above date format */
        memset (ldate, 0, sizeof(ldate));
        
        struct timeval tv;
        struct tm *ptm;
        gettimeofday(&tv,NULL);
        ptm=localtime(&tv.tv_sec);
        //Get formats for Year, month, day, time, milliseconds
        /* TODO: delete below */
        /*my_strftime(year, sizeof(year), "%Y", localtime(&tvec));
        my_strftime(month, sizeof(month), "%m", localtime(&tvec));
        my_strftime(day, sizeof(day), "%d", localtime(&tvec));
        my_strftime(time, sizeof(time), "%H:%M:%S",localtime(&tvec));*/
        strftime(year, sizeof(year), "%Y",ptm);
        strftime(month, sizeof(month), "%m", ptm);
        strftime(day, sizeof(day), "%d", ptm);
        strftime(time, sizeof(time), "%H:%M:%S",ptm);
        millisec=tv.tv_usec/1000;
        
        //Create the directory structure        
        char *yeardir;
        char *monthdir;
        asprintf(&yeardir,"%s/%s",log_dir,year);
        asprintf(&monthdir,"%s/%s",yeardir,month);
        
        /*my_strftime(ldate, sizeof ldate, "%Y.%m.%d-%H:%M:%S.log", localtime(&tvec));*/
        sprintf(ldate,"%s.%s.%s-%s.%.6d.log",year,month,day,time,millisec);
        //sprintf(ldate,"%s.log",year);
        printf("ldate:%s\n",ldate);

        asprintf(&fname,"%s/slogd-%s-%s",monthdir,worker->fqdn,ldate);
        /* end log name format */
        
        /* TODO: here...some king of mutex/sefimore to  handel threeads */
        
        /* Verify we can write to yearpath */
        mode_t  mode = CREATE_DIR_MODE;
        mode_t old_umask = umask (002); /* allow group write bit for mkdir */
        
        int e=0; //err number
        if (access(yeardir,W_OK)==-1) {
            // cant write to yeardir, or doesn't exist 
            e=errno; //get the error
            //printf("Darn: got error e:%d ENOENT:%d\n",e,ENOENT);
            if (e == ENOENT ) { //path doesn't exist, lets create
                if (mkdir(yeardir,mode) != 0) {
                    log_info(1024,"Error: unable to create directory: %s\n",yeardir);
                    log_info(1024,"Verify it exists and owned by user:group %s:%s\n",STRINGIFY(DEF_USER),STRINGIFY(DEF_GROUP));
                    /* TODO: Release the mutex lock */
                    goto cleanup;
                }
            }
            else { //cant write to yearpath
                
                log_info(1024,"Error: unable to write to directory: %s\n",yeardir);
                log_info(1024,"Verify it exists and owned by user:group %s:%s\n",STRINGIFY(DEF_USER),STRINGIFY(DEF_GROUP));
                /* TODO: Release the mutex lock */
                goto cleanup;
            }
        } //end if we can write to yearpath
        /* verify we can write to monthpath */
        e=0;
        if (access(monthdir,W_OK)==-1) {
            //cant write to monthpath, or doesn't exist...
            e=errno; //get the error
            if (e==ENOENT ) { //path doesn't exist, lets create
                if (mkdir(monthdir,mode) != 0) {
                    log_info(1024,"Error: unable to create directory: %s\n",monthdir);
                    log_info(1024,"Verify it exists and owned by user:group %s:%s\n",STRINGIFY(DEF_USER),STRINGIFY(DEF_GROUP));
                    /* TODO: Release the mutex lock */
                    goto cleanup;
                }
            }
            else { //cant write to monthpath
                log_info(1024,"Error: unable to write to directory: %s\n",monthdir);
                log_info(1024,"Verify it exists and owned by user:group %s:%s\n",STRINGIFY(DEF_USER),STRINGIFY(DEF_GROUP));
                /* TODO: Release the mutex lock */
                goto cleanup;
            }
        } //end if we can write to monthpath
        
        /* reset the umask */
        umask(old_umask);
        fscript = fopen(fname, "w"); 

        if (fscript == NULL) {
            log_info(1024,"Error: Creating file %s failed: %s\n",fname,strerror(errno));
            log_info(1024,"Verify directory exists and owned by user:group %s:%s\n",STRINGIFY(DEF_USER),STRINGIFY(DEF_GROUP));
            /* TODO: Release the mutex lock */
            goto cleanup;
        }
        /* set read only to user and group */
        if (fchmod(fileno(fscript),0440)!=0) {
            log_info(1024,"Warning: unable to change permissions on %s\n  Session log may not be secure\n",fname);
            /* TODO: Release the mutex lock */
            /* TODO: move above file create mode to config.h or ssloger.conf */
            goto cleanup;
        } 
    /* End logfile format and dir creation */   
  
    /* log users request to the master log */
    char *message;
    asprintf(&message,"host:%s; logfile:%s; pid:%d; %s",worker->fqdn, fname, getpid(), logString);
    if (logCmd(message,logfname)!=0) {
        log_info(1024,"Killing connection");
        gnutls_bye (worker->session, GNUTLS_SHUT_RDWR);
        /* TODO: Release the mutex lock */
        goto cleanup;
    }
    
    /* Success write, TODO: release the mutex lock */
    /*if(pthread_mutex_unlock(&global_data_mutex)!=0) {
        log_info(1024,"proccess_connection::mutex unlock failed\n");
        goto cleanup;
        return;
    }*/ 
    
    if (debug>2) 
        log_info(1024," released lock\n");
    
    //usleep(1000);
    
    /* Send the client OK ack */
    char *ok;
    // sending back the logfile "slogd-<hostname>-date
    asprintf(&ok,"logfile:slogd-%s-%s",worker->fqdn,ldate);
    ret=gnutls_record_send (worker->session, ok, strlen (ok));
    if (ret == 0)
    {
        if (debug > 1) 
            log_info (1000,"Peer has closed the GNUTLS connection\n");
        goto cleanup;
    }
    else if (ret < 0)
    {   
        if (debug>1) 
            log_info(1000, "*** Received corrupted data after sending OK (%s). Closing the connection\n",gnutls_strerror(ret));
        /*TODO print the tls error*/
        goto cleanup;
    }   
    
    /* process socket data here */
    for (;;)
    { 
        memset (buffer, 0, MAX_BUF + 1); //TODO: define buffer 
        ret = gnutls_record_recv (worker->session, buffer, MAX_BUF);
        
        if (ret == 0)
        {
            /* We dont need to log happy session closes  */
            /* char *wmsg="Peer has gracefully closed the GNUTLS connection\n";
             fwrite(wmsg,1,strlen(wmsg),fscript);
            */
            if (debug > 1) 
                log_info (1000,"** Peer has gracefully closed the GNUTLS connection\n");
            break;
        }
        else if (ret < 0)
        {   
            /* log unhappy client termination to logfile */
            char *wmsg="\n*** Recieved unexpeced/corrupeded data. Closing client connection\n";
            fwrite(wmsg,1,strlen(wmsg),fscript);
            log_info(1000, "*** Received corrupted data(%s) in reading client data. Closing the connection\n", gnutls_strerror(ret));
            break;
        }
        else if (ret > 0)
        {
            /* log the input */
            int fwret=fwrite(buffer, 1, ret, fscript);
            
            /*if (debug>8) 
                log_info(1024,"Writing to logfile:%s data:%s",fname,buffer);
            */

            if (fwret!=ret) {
                log_info(1024,"Error logging to slogd file: %s\n",fname);
                /* todo, use  ferror to debug */
                goto cleanup;
            }
            /* flush the buffer, commit to disk */
            if (fflush(fscript)!=0) { 
                /* TODO get ferror num */
                log_info(1024,"Error fushing data to disk\n");
                goto cleanup;
            }
           
            if (ferror(fscript)) {
                log_info(1024,"Error  writing to %s:%s\n",fname,strerror(errno));
                break;
                goto cleanup;      
            }
            
            
            if (debug>4) 
                log_info(1024,"fwrite returned %d\n",fwret);
        }
    }

    /* do not wait for the peer to close the connection.
    */
    gnutls_bye (worker->session, GNUTLS_SHUT_WR);   
    goto cleanup;
        
    cleanup:
        printf("Cleanup!!!\n");
        if (fscript!=NULL) {
            if (debug>1) log_info(1000,"Closing fscript\n");
            fflush(fscript);
            fclose(fscript);
        }
        if (debug>1) log_info(200,"closing worker->socket\n");
        close (worker->socket);
        if (debug>1) log_info(200,"closing session\n");
        /* Remove this sesson the gnutls sessions db TODO:testing... */
        gnutls_db_remove_session(worker->session);
        gnutls_deinit (worker->session);
        if (debug>1) log_info(200,"freeing worker\n");
        virFree(worker); 
        return;
} // end proccess_connection_fork


#define LINE_LEN 100
int read_conf( const char* conf_file,const char *key, char **value) {
    //reads config_file looking fir key,
    // sets  value if found, null otherwise
    // returns -1 on FNF, 0 on keynot found, 1 on found
    FILE *fp;
    char line[LINE_LEN];
    int end;
    int keyLen=strlen(key);
    fp = fopen(conf_file, "r");
    if (fp == NULL ) {
        fprintf ( stderr,"Can't open config file: %s\n",conf_file);
        return(-1); /* Can't open file */
    }
    
    while (fgets(line, LINE_LEN, fp)) {
        /* All options are key=value (no spaces)*/
        if (line == NULL) continue;
        if (strncmp(line, key, keyLen) == 0) { //we have a match //we have a match
            end = strlen(line);
            if (line[end-1] == '\n')
                line[end-1] = 0; /* Remove trailing newline */
                *value = strdup(line+keyLen+1); //add equal to  key=val
                if (debug>0) log_info(1000,"read_conf: file %s: found key:%s val:%s \n",conf_file,key,*value);
                if (fp!=NULL) fclose(fp);
                return(1); //happy return
        }
    }
    return 0; //unhappy return
}

static int writePidFile(const char *pidFile) {
    int fd;
    FILE *fh;
    
    if (debug>0)
        log_info(1000,"pid_file=%s\n",pidFile);
    
    if (pidFile[0] == '\0')
        return 0;    
    
    if ((fd = open(pidFile, O_WRONLY|O_CREAT|O_EXCL, 0644)) < 0) {
        log_info(1000,"Failed to open pid file: %s\n",pidFile);
        return -1;
    }
    
    if (!(fh = fdopen(fd, "w"))) {     
        log_info(1000,"Failed to fdopen pid file: %s\n",pidFile);
        close(fd);
        return -1;
    }
    
    if (fprintf(fh, "%lu\n", (unsigned long)getpid()) < 0) {
        log_info(1000,"Failed to write to pid file: %s\n",pidFile);
        fclose(fh);
        return -1;
    }
    
    if (fclose(fh) == EOF) {
        log_info(1000,"Failed to close pid file: %s\n",pidFile);
        return -1;
    }
    
    return 0;
}

void termination_handler (int signum)  { /* signal handler function */
switch(signum){
    log_info(1024,"Debug: in termination_handler\n");
    case SIGHUP:
        log_info(1024,"SIGNAL HUP recieved");
        /* reload config file */
        return;
        break;    
    case SIGTERM:
        /* finalize the server */
        if (pid_file)
          unlink (pid_file);
        forever = 0; 
        exit (0); //hard exit
        break;    
    case SIGQUIT:
        /* finalize the server */
        if (pid_file)
            unlink (pid_file);
        forever = 0; 
        exit (0);
        break;  
    case SIGINT:
        /* finalize the server */
        if (pid_file)
            unlink (pid_file);
        forever = 0; 
        exit(0);
        break;          
    case SIGCHLD:
        //log_info(1024,"In SIGCHLD Reaper\n");
        while (waitpid (-1, NULL, WNOHANG) > 0);
              /* don't hang, if no kids are dead yet */
        usleep (2000);    
        //wait3(NULL,WNOHANG,NULL);
        break;
    } 
    
    
    /*Stop the listening cycle, need to open a conection to socket to stop the accept */    
    //signal (signum, termination_handler);
}

void
readConfigFile (void) {
    /* only port and debug values can be overided on the cmd line */
    /* read config file and set the values for:
        debug
        port
        listenIP
        pid_file
        ca_file
        key_file
        cert_file 
        crl_file
        tls_verify_certificate
        tls_no_verify_host
        use_tls_pks
    */
    char *port_str;
    char *debug_str;
    char *listenIP_str;
    char *tls_verify_certificate_str;
    char *tls_no_verify_host_str;
    char *use_tls_pks_str; 
    char *use_tls_cert_str;
    char *use_tls_anon_str;
    
    /* port */
    if (read_conf(conf_file,"port",&port_str)==1) {
        port=atoi(port_str);
    }
    
    /* debug */
    if (read_conf(conf_file,"debug",&debug_str)==1) {
        int t_debug=0;
        t_debug=atoi(debug_str);
        /* only set the debug on from the config file if debug is currently 0 
        * ie..it was not changed on the cmd line  */
        if (debug==0) 
            debug=t_debug; 
    }
    
    /* TODO: listenIP */
        
    /* pid_file */
    if (strcmp(SLOGDPIFFIE,pid_file)==0)  {
        /* pid_file was not modified on the cmd line, use conf_file settings */
        read_conf(conf_file,"pid_file",&pid_file); 
    }
    
    read_conf(conf_file,"ca_file",&ca_file);     /* ca_file */
    read_conf(conf_file,"key_file",&key_file);   /* key_file */
    read_conf(conf_file,"cert_file",&cert_file); /* cert_file */
    read_conf(conf_file,"crl_file",&crl_file);   /* crl_file */

    /* tls_no_verify_host */
    if (read_conf(conf_file,"tls_no_verify_host",&tls_no_verify_host_str)==1) 
        tls_no_verify_host=atoi(tls_no_verify_host_str);
 
    /* use_tls_cert */
    if (read_conf(conf_file,"use_tls_cert",&use_tls_cert_str)==1) 
        use_tls_cert=atoi(use_tls_cert_str);    
    
    /* use_tls_pks */
    if (read_conf(conf_file,"use_tls_anon",&use_tls_anon_str)==1) 
        use_tls_anon=atoi(use_tls_anon_str);
    
    /* use_tls_pks */
    if (read_conf(conf_file,"use_tls_pks",&use_tls_pks_str)==1) 
        use_tls_pks=atoi(use_tls_pks_str);
    
    /* Do we need to verify client certificates */
    if (read_conf(conf_file,"tls_verify_certificate",&tls_verify_certificate_str)==1)
        tls_verify_certificate=atoi(tls_verify_certificate_str);
    
}

int
main (int argc, char **argv)
{
    int err; 
    int ret;
    long sd, listen_sd; /* bumped from int to long required by gnutls_transport_set_ptr*/
    struct sockaddr_in sa_serv;
    struct sockaddr_in sa_cli;
    int client_len;
    char topbuf[512];
    //gnutls_session_t session;
    int optval = 1;
    extern int optind;
    int ch;
    char *p;  

    progname = argv[0];
    if ((p = strrchr(progname, '/')) != NULL)
        progname = p+1;
    
    
    if (argc == 2) {
        if (!strcmp(argv[1], "-V") || !strcmp(argv[1], "--version")) {
            printf("%s (%s)\n",
                   progname, STRINGIFY(VERSION));
                   return 0;
        }
    }
    

        
    while ((ch = getopt(argc, argv, "dv:c:p:")) != -1)
        switch((char)ch) {
            case 'd':
                /* fork off as daemon */
                godaemon=1;
                break;
            case 'v':
                /* verbose debugging (1-10) */
                debug=atoi(optarg);
                break;
            case 'c':
                /* set config file */
                conf_file=optarg;
                break;
            case 'p':
                pid_file=optarg;
                break;
            case '?':
            default:
                fprintf(stderr,"usage: %s [-d] [-v <1-9>] [-p pidfile]\n",progname);
        }
    argc -= optind;
    argv += optind;

    /* Make sure conf_file  is set */
    if (checkFile("slogd config file",conf_file) < 0) {
        return 1;
    }
    /* read and set options from conf file here
    *  options on cmdline overide conf file settings
    */
    readConfigFile();
    
    /* Check to verify only one auth method is chosen in config file */
    if (use_tls_pks+use_tls_cert+use_tls_anon!=1) {
        fprintf(stderr,"Only one tls authenticiton method can be specified\n");
        log_info(1000, "Only one tls authenticiton method can be specified\n");
        _exit(1);
    }
    
    
    /* Good to go, initialize TLS */
    if ( initializeGnuTLS() < 0 ) {
        log_info(1000,"Error initalizing tls\n");
        return 1;
    }
    
    /* Socket operations
    */
    listen_sd = socket (AF_INET, SOCK_STREAM, 0);
    if ( socket (AF_INET, SOCK_STREAM, 0) ==-1) {
        log_info(1000,"Error: socket - %s\n",strerror(errno));
        return 1;
    }       
    memset (&sa_serv, '\0', sizeof (sa_serv));
    sa_serv.sin_family = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY; /*TODO: set this to the listen adddress from config file*/
    sa_serv.sin_port = htons (port);	/* Server Port number */
    
    if (setsockopt (listen_sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (int))==-1) {
        log_info(1000,"Error: setsockopt - %s\n",strerror(errno));
        return 1;
    }    

    if (bind (listen_sd, (SA *) & sa_serv, sizeof (sa_serv))==-1) {
        log_info(1000,"Error: bind - %s\n",strerror(errno));
        return 1;
    }

    if (listen (listen_sd, 1024)==-1){
        log_info(1000,"Error: listen - %s\n",strerror(errno));
        return 1;
    }

    log_info(1000,"%s started, listening on port %d with pid %d\n",progname, port, getpid());


    /* fork off as daemon */
    if (godaemon) {
        if (goDaemon()<0) {
            log_info(1000,"Error: Unable to fork daemon\n");
            return 1;
        }
    }
    else {
        /* set up signal handlers */
        if (debug >2 ) log_info(1024,"Setting signals\n");
        signal(SIGCHLD, termination_handler);
        signal (SIGTERM, termination_handler);
        signal (SIGQUIT, termination_handler);
        signal (SIGHUP, termination_handler);
    }

    writePidFile(pid_file); 
    
    client_len = sizeof (sa_cli);
    while (forever)
    {
      
        sd = accept (listen_sd, (SA *) & sa_cli, &client_len);
        struct worker_pthread *worker;
         
        if (debug>1)
            log_info(1000,"Initalizing worker\n");
        if (virAlloc(&(worker),sizeof(*(worker))) < 0) {
            log_info(1000,"Error: Unable to alloc mem for worker thread\n");
            close (sd);
            continue;
        }
    
        if (debug>1)
            log_info(1000,"the memory address of worker is:%d\n",worker);   
        worker->socket=sd;
        worker->server=listen_sd;
        worker->session = initialize_tls_session ();
        worker->cli_port=ntohs(sa_cli.sin_port);
        
        if (worker->session == NULL) {
            //certifacate validation failed
            close (sd);
            gnutls_deinit (worker->session);
            log_info(1000, "*** TLS session has failed (%s)\n",
                     gnutls_strerror (ret));
            virFree(worker);
            continue; // we cant set up tls session, so go back to listening
        }        
 
        char fqdn[MAXFQDNLEN];
        struct hostent *client_hostent;
        client_hostent = gethostbyaddr((const char*)&sa_cli.sin_addr, sizeof(struct in_addr), AF_INET);
        if( client_hostent != NULL ) {
            /* choose either hostname or IP for logging */
            strcpy(fqdn,client_hostent->h_name);
            strcpy(worker->fqdn,client_hostent->h_name);
        }
        else
            strcpy(fqdn,inet_ntop (AF_INET, &sa_cli.sin_addr, topbuf,sizeof (topbuf)));

        if (debug>1)
            log_info(1000,"Connection from: %s port %d\n",fqdn,ntohs (sa_cli.sin_port));

        /* fork off a thread to handel the connection */
        int fpid;
        fpid = fork();
        if (fpid < 0)
            log_info(1024,"ERROR on fork");
        if (fpid == 0)  {
            close(listen_sd); /* child closes listening socket */
            proccess_connection_fork(worker);
            _exit(0);
        }
        else close(sd); /* parent closes accepted socket */
        
        
        /* fork off a pthread to handel connection */
//         printf("Debug1\n");
//         pthread_attr_t attr;
//         printf("Debug1\n");
//         pthread_attr_init(&attr);
//         printf("Debug1\n");
//         pthread_t thread;
//         printf("Debug1\n");
        
//         if (debug>1)
//             log_info(1000,"forking thread\n");
//         /* fork a worker process to manage data */
//         int rc = pthread_create(&(thread), NULL, (void *) &proccess_connection, worker);
//         if (rc!=0) {
//             log_info(1000,"Error: pthread_create failed");
//             virFree(worker);
//             close(sd);
//         }
//         else 
//             pthread_detach(thread);

    } /* end listenining on server socket */
    close (listen_sd);

    gnutls_certificate_free_credentials (x509_cred);
    gnutls_anon_free_server_credentials(anon_cred);

    /* not avail on < tls v2.v
    gnutls_priority_deinit (priority_cache);
    */
    
    gnutls_global_deinit ();
    return 0;
}
