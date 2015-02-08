/*
* Copyright (c) 1980 Regents of the University of California.
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
* 3. All advertising materials mentioning features or use of this software
*    must display the following acknowledgement:
*	This product includes software developed by the University of
*	California, Berkeley and its contributors.
* 4. Neither the name of the University nor the names of its contributors
*    may be used to endorse or promote products derived from this software
*    without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
*/

/*
* 1999-02-22 Arkadiusz Mi�kiewicz <misiek@pld.ORG.PL>
* - added Native Language Support
*
* 2000-07-30 Per Andreas Buer <per@linpro.no> - added "q"-option
*/

/*
* 2009-01-20 Ed Brand <ebrand@brandint.com>
*  - Modified to allow logging of keystrokes to a file
*  - This file is based off a  modified version of the script.c 
*    source code mentioned in the above Copyright
*/
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/signal.h>
#include <syslog.h>
#include <pwd.h>
#include <errno.h>
#include <locale.h>
#include "nls.h"
#include "config.h"

#ifdef __linux__
#include <unistd.h>
#include <string.h>
#include <paths.h>
#endif 

// fix for Solaris lack of paths.h
#ifndef _PATH_BSHELL
#define _PATH_BSHELL "/bin/bash"
#endif

#ifdef HAVE_LIBUTIL
#include <pty.h>
#endif

#include "tlstools.h"
#include <gnutls/gnutls.h>
#include <gcrypt.h> /* for gcry_control */



/* Prototypes */
void finish(int);
void done(void);
void fail(void);
void resize(int);
void fixtty(void);
void getmaster(void);
void getslave(void);
void doinput(void);
void dooutput(void);
void doshell(void);
void do_setuid(void);
void undo_setuid(void);
void do_setgid(void);
void undo_setgid(void);
int read_conf(const char *, char **);
int readConf(void);
int logCmd2(char *, char *, char *,char *, char *);
int createSlog(void);
//int slogdConnect(char *);
int slogdSend (void *slogMsg, int size);
int mygetline(char *, int);

char	*shell;
FILE	*fscript;
FILE    *pinput; // pipe command input
int	master;
int	slave;
int	child;
int	subchild;
char	*fname; 
char	*sfname; //short file name
char	*comment;
int commentLen=0; //length of comment after entering reason
struct  passwd *upasswd;
struct	termios tt;
struct	winsize win;
int	lb;
int	l;
#ifndef HAVE_LIBUTIL
char	line[] = "/dev/ptyXX";
#endif
char	*cflg = NULL;
int	debug=0;
int	fflg = 0;
int	hflg = 1;  //on by default
int	qflg = 0;
int	tflg = 0;
char *ruser;
static char *progname;
const char *header=STRINGIFY(HEADER_LABEL);


/* tlstools_client vars */
gnutls_session_t session;
long socket_sd; /* socket for tls session */
char remote_logfile[MAX_REMOTE_LOGFILE_LEN]; /* logfile name returned by slogd server */


char *slogd_server=NULL; /* set in readConf() */
int require_remote_slogd; /* default value set in readConf()  */
int keep_local_logs; /* default value set in readConf() */

int slogdIsConnected=0; /* set to 1 when a conection is establihed */
int slogdHasBeenConnected=0; /* set to 1 when a connection is established,
                                Used to determine if client was ever connected */
int slogdLostConnection=0; /* set to 1 when connection is lost */
  /* TODO: above var no longer used, delete from code */

/* defaults if no sslogger.conf */
int log_all_cmds=0;
int commentSize=100; //Max comment len //TODO: change name to max_comment to match config name
int minCommentSize=0; //Min comment len //TODO: change name to min_comment to match config name
int allow_user_replay=1; //allow user read their own logs

#define LINE_LEN 100
int read_conf( const char *key, char **value) {
    //reads config_file looking first key, 
    // sets  value if found, null otherwise
    // returns -1 on FNF, 0 on keynot found, 1 on found
    FILE *fp;
    char line[LINE_LEN];
    int end;
    int keyLen=strlen(key);
    const char *conf_file=STRINGIFY(CONF_FILE);
    //if (*value!=NULL) free(*value);
    fp = fopen(conf_file, "r");    
    if (fp == NULL ) {
        fprintf ( stderr,"Can't open config file: %s\n",conf_file);
        return(-1); /* Can't open file */
    }
    
    while (fgets(line, LINE_LEN, fp)) {
        /* All options are key=value (no spaces)*/
        if (line == NULL) continue;        
        //if (debug) printf("line:%s",line);
        if (strncmp(line, key, keyLen) == 0) { //we have a match //we have a match
            end = strlen(line);
            if (line[end-1] == '\n')
                line[end-1] = 0; /* Remove trailing newline */
            if (line[end-2] == '=') { /* Value is null, return 1; unhappy */
                return 0; /*TODO: test and push this if to slogd-server */
            }
                
        *value = strdup(line+keyLen+1); //add equal to  key=val
        if (debug) printf("Found key:%s val:%s\n",key,*value);
        if (fp!=NULL) fclose(fp);
        return(1); //happy return
        }
    }
    return 0; //unhappy return
}

/* Remember the effective and real UIDs. */
static uid_t euid, ruid;
static gid_t geuid,gruid;

static void
die_if_link(char *fn) {
    struct stat s;
    if (lstat(fn, &s) == 0 && (S_ISLNK(s.st_mode) || s.st_nlink > 1)) {
        fprintf(stderr,
            _("Warning: `%s' is a link.\n"
            "Use `%s [options] %s' if you really "
            "want to use it.\n"
            "Sslogger not started.\n"),
            fn, progname, fn);
        exit(1);
    }
}

/*
* Stop extremely silly gcc complaint on %c:
*  warning: `%c' yields only last 2 digits of year in some locales
*/
static void
my_strftime(char *buf, size_t len, const char *fmt, const struct tm *tm) {
    strftime(buf, len, fmt, tm);
}

int logCmd2(char *user, char *asUser, char *cmd, char *keyLogfname, char *reason) {
    char *message;
    char *logfname;
    const char *log_dir=STRINGIFY(LOG_DIR);
    const char *log_file=STRINGIFY(LOGFILE);
    asprintf(&logfname,"%s/%s",log_dir,log_file);
    do_setuid();
    do_setgid();
    FILE *log;
    log=fopen(logfname,"a");
    
    if (log == NULL ) {
        /* Can't open file */
        if (debug) {
            printf ("set euid: %d\n",euid); //suid user
            printf ("real ruid: %d\n",ruid); //real user
        }
        undo_setuid();
        undo_setgid();
        fprintf ( stderr,"Error: can't open logfile: %s\n",logfname);
        sleep(1);
        return (0);
        
    }

    /*time format for logfname*/
    char outstr[200];
    time_t t;
    struct tm *tmp;
    t = time(NULL);
    tmp = localtime(&t);
    if (tmp == NULL) {
        perror("localtime");
        exit(EXIT_FAILURE);
    }
    if (strftime(outstr, sizeof(outstr), "%F %H:%M:%S", tmp) == 0) {
        fprintf(stderr, "strftime returned 0");
        undo_setuid();
        undo_setgid();
        exit(EXIT_FAILURE);
    } 
  
    if (debug) printf("opening log file %s\n",logfname);
    int p=getpid(); //get the pid
    fprintf(log,"%s %s[%d];",outstr,progname,p);
    //fprintf(log," user:%s; as:%s; %s; logfile:%s; reason:%s\n",user,asUser,cmd,keyLogfname,reason);
    fprintf(log," user:%s; as:%s; %s; logfile:%s; reason:%s\n",user,asUser,cmd,fname,reason);
    fclose(log);
 
    if (slogd_server!=NULL) {
        /* Connect to slogd Server if defined in ssloger.conf */
        char *slogMsg;
        asprintf (&slogMsg,"clientLogFile:%s; %s[%d]; user:%s; as:%s; %s; reason:%s\n",fname,progname,p,user,asUser,cmd,reason);
        if (debug>0) fprintf (stderr,"DEBUG: Connect string %s\n",slogMsg);
        /* Connect to remode slogd server */
        slogdIsConnected=slogdConnect(slogMsg); /* connect to slog server and set flag */
    }

    /* put slogdServer and SlogdLogID into local and remote log file */
    if ((!qflg)) {
        printf("SlogdServer:");
	if (slogd_server!=NULL) printf ("%s\n",slogd_server);
        printf("SlogdLogID: %s\n\n",remote_logfile);
    }
    if (fscript !=NULL) {
      fputs("SlogdServer:",fscript);
      if (slogd_server!=NULL)
        fputs(slogd_server,fscript);
      fputs("\r\n",fscript);
      fputs("SlogdLogID:",fscript);
      if (remote_logfile)
        fputs(remote_logfile,fscript);
      fputs("\r\n\r\n",fscript);
    }
    
    if ( slogdIsConnected==1) {
        if (debug > 0) fprintf (stderr,"DEBUG: Slogd connection establihed\n");
        /* put slogdServer and SlogdLogID into local and remote log file */
        slogdSend("SlogdServer:",strlen("SlogdServer:"));
        if (debug > 0) fprintf (stderr,"DEBUG: 1");
        slogdSend(slogd_server,strlen(slogd_server));
        if (debug > 0) fprintf (stderr,"DEBUG: 1");
        slogdSend("\r\n",strlen("\r\n"));
        if (debug > 0) fprintf (stderr,"DEBUG: 1");
        slogdSend("SlogdLogID:",strlen("SlogdLogID:"));
        if (debug > 0) fprintf (stderr,"DEBUG: 1");
        slogdSend(remote_logfile,strlen(remote_logfile));
        if (debug > 0) fprintf (stderr,"DEBUG: 1");
        slogdSend("\r\n\r\n",strlen("\r\n\r\n"));
        /* flip slogdHasBeenConnected switch 
            Used to set policy when a conection is dropped */
        slogdHasBeenConnected=1;
        if (debug > 0) fprintf (stderr,"DEBUG: remote session initalized\n");
    }
    else { /* Connection could not be established */
        if (require_remote_slogd==1) {
            if (slogd_server==NULL)
                fprintf (stderr,"\nError: slogd_server is not set in sslogger.conf\n");
            printf("\nA policy on this host requires sslogger to log to a remote slogd server.");
            printf(" If you think you reached this message in error, ask your system administrator to modify the \"require_remote_slogd\" setting in sslogger.conf\n");
            /* TODO: do we need to suid/sgid to ulink? */
            unlink(fname);  /* remove the log file as it is empty */
            exit(EXIT_FAILURE);
        }
        
        else { /* can not establish slog connection, but require_remote_slogd==0 */
            if (  require_remote_slogd==0) 
              printf ("Sslogger continuing with local logging enabled.\n\n");
        }
    }
 
    /* output reason why cmd or shell was invoked */
    if (debug > 0) fprintf (stderr,"DEBUG: reason\n");
    char *reasonMsg;
    if ((!cflg))
        asprintf(&reasonMsg,"Reason %s invoked interactive shell for %s: ",ruser,upasswd->pw_name);
    else
      asprintf(&reasonMsg,"Reason %s invoked cmd: \"%s\" for %s: ",ruser,cflg,upasswd->pw_name);
    if (fscript!=NULL)
        fprintf(fscript,"%s",reasonMsg);
    slogdSend(reasonMsg,strlen(reasonMsg));
    if (fscript!=NULL)
        fputs(comment,fscript);
    slogdSend(comment,strlen(comment));
    asprintf(&reasonMsg,"\r\n\r\n");
    slogdSend(reasonMsg,strlen(reasonMsg));
    if (fscript!=NULL)
        fputs("\r\n\r\n",fscript);
    
    if ((!cflg) && (strlen(reason) > commentSize) && (minCommentSize>0) ) { 
        /* cflag - command to run (non interactive)
        *  minCommentSize - the minimum comment len, if zero, there is no comment "(null)"
        *  commentSize - maximum comment len for syslog comments, if zero no comment is required
        *  reason - is the comment, (null) if commentSize=0
        */
        if (debug) {
            printf("whacking comment len to:%d\n",commentSize);
            printf("reason-length:%d syslogCommentSize:%d minCommentSize:%d\n",strlen(reason),commentSize,minCommentSize);
        }
        reason[commentSize]='\0';
    }

    asprintf(&message,"user:%s; as:%s; %s; logfile:%s; reason:%s\n",user,asUser,cmd,keyLogfname,reason);
    //openlog (progname, LOG_PID,LOG_AUTHPRIV);
    syslog(LOG_INFO,message);
    //closelog();
    undo_setuid();
    undo_setgid();
    return 1; //happy ending
}


/* Read slogger.conf an set global vars */
int readConf (void) {
    commentSize=MAXCOMMENTSIZE; //set default size
    minCommentSize=MINCOMMENTSIZE; //dito
    /* Get options from config file */
    char *value;
    int found=0;
    found=read_conf("log_all_cmds",&value);
    if (found==1) {
        //printf ("found, result is: %s\n",value);
        if (log_all_cmds==0) /* only overide if -l not passed on cmd line */
          log_all_cmds=atoi(value); /* set to file value */
    }
    
    found=read_conf("max_comment",&value);
    if (found==1) {
        //printf ("found, result is: %s\n",value);
        commentSize=atoi(value);
    }
    
    found=read_conf("min_comment",&value);
    if (found==1) {
          //printf ("found, result is: %s\n",value);
        minCommentSize=atoi(value);
    }

    found=read_conf("allow_user_replay",&value);
    if (found==1) {
          //printf ("found, result is: %s\n",value);
        allow_user_replay=atoi(value);
    }

    /* TODO: use below formay for above, and also slogd-server */
    
    /* slogd server */
    found=read_conf("slogd_server",&value);
    if (found==1) { /* we found the key, set the value */ 
        slogd_server=strdup(value);
        tlstools_client_server=slogd_server;
    }
    else {
        tlstools_client_server=NULL;
        slogd_server=NULL;
    }
    
    /* tlsclient Auth type */
    tlstools_client_authtype=TLSTOOLS_AUTH_ANON; /* set default to anon */
    if (read_conf("slogd_authtype",&value)==1) { /* we found the key, set the value */ 
        if (strcmp(value,"x509")==0)
            tlstools_client_authtype=TLSTOOLS_AUTH_X509CERT;
        if (strcmp(value,"anon")==0) 
            tlstools_client_authtype=TLSTOOLS_AUTH_ANON;
    }
  
    /* slogd_server_port */
    tlstools_client_serverport=5556; /* default port */
    if (read_conf("slogd_server_port",&value)==1) { /* we found the key, set the value */ 
        tlstools_client_serverport=atoi(value);
    }
    
    /* require_remote_slogd */
    require_remote_slogd=0; /* set to default 0, not required */
    if (read_conf("require_remote_slogd",&value)==1) { /* we found the key, set the value */ 
        require_remote_slogd=atoi(value);
    }

    /* keep_local_logs */
    keep_local_logs=1; /* set to default 1, always keep local logs */
    if (read_conf("keep_local_logs",&value)==1) { /* we found the key, set the value */ 
        keep_local_logs=atoi(value);
    }

/* TODO:  
  hook to unlink local log file if   keep_local_logs=0 
   
*/

    if (debug) printf("log_all_cmds=%d\n",log_all_cmds);
    if (debug) printf("Max commentSize=%d\n",commentSize);
    if (debug) printf("minCommentSize=%d\n",minCommentSize);
    if (debug) printf("allow_user_replay=%d\n",allow_user_replay);
    if (debug && tlstools_client_server!=NULL) printf("slogd_server=%s\n",tlstools_client_server); //slogd_server);
    if (debug) printf("slogd_server_port=%d\n",tlstools_client_serverport );
    if (debug) printf("tlstool_authtype=%d\n",tlstools_client_authtype);
    if (debug) printf("require_remote_slogd=%d\n",require_remote_slogd);
    if (debug) printf("keep_local_logs=%d\n",keep_local_logs );
    
    return 1; //happy read
    
}

int 
createSlog (void) {
    /*Creates directories, sets permissions, and opens log file */
    /* log name format in fname*/
    char hname[MAXHOSTNAMELEN];
    (void) gethostname(hname,sizeof(hname));
    //get user
    //ruser=getpwuid(geteuid())
    ruser=getlogin(); 
    if (ruser == NULL ) { //getlogin failed, try another method to get user ID
        ruser=getenv("LOGNAME"); //sudo sets LOGNAME
            if (ruser == NULL ) {
                printf("Unable to determine user login id\n");
                exit(EXIT_FAILURE);
        }
    }
    time_t tvec;
    char ldate[BUFSIZ];
    tvec = time((time_t *)NULL);
    if (debug) {
        printf ("set euid: %d\n",euid); //suid user
        printf ("real ruid: %d\n",ruid); //real user
    }

    //get the ruid passwd entry for the process
    upasswd=getpwuid((uid_t)ruid);
    if (!upasswd) {
        printf("Unknown euid, exiting\n");
        exit(EXIT_FAILURE);
    }

    if (! (upasswd->pw_shell && upasswd->pw_name && upasswd->pw_name[0] 
              && upasswd->pw_dir && upasswd->pw_dir[0] && upasswd->pw_passwd)) {
        printf("Bad password entry for uid:%d, exiting\n",ruid);
        exit(EXIT_FAILURE);
    }

    shell=upasswd->pw_shell;
    if (debug) printf("DEBUG: ruid:%s shell:%s\n",upasswd->pw_name,shell);
    if (shell == NULL)
        shell = _PATH_BSHELL;
    setenv("SHELL",shell,1);

    /* Only open fscript if we are going to write data to it.
      1) if cflg - we have a cmd to execute
         if log_all_cmds==1 -> open the file
         else return 
      2) interactive shell -> open the file
    */
    if (cflg) {
        if  (log_all_cmds==0)  {// do not log cmd output
        if (debug) printf("Logging cmd output: off\n");
        fname="Logging cmd output disabled";
        sfname="Logging cmd output disabled";
        return 1;
        }
    }   
    if (debug) printf("Logging cmd output: on\n");
    // create and use LOG_DIR/sl/<year>/<month>/$sfname
    char year[10];
    char month[10];
    char day[10];
    char time[30];
    //Get formats for Year, month, day, time
    my_strftime(year, sizeof(year), "%Y", localtime(&tvec));
    my_strftime(month, sizeof(month), "%m", localtime(&tvec));
    my_strftime(day, sizeof(day), "%d", localtime(&tvec));
    my_strftime(time, sizeof(time), "%H:%M:%S",localtime(&tvec));
    
    //Create the directory structure
    const char *log_dir=STRINGIFY(LOG_DIR);
    char *yeardir;
    char *monthdir;
    asprintf(&yeardir,"%s/%s",log_dir,year);
    asprintf(&monthdir,"%s/%s",yeardir,month);

    /* Verify we can write to yearpath */
    mode_t  mode = CREATE_DIR_MODE;
    mode_t old_umask = umask (002); /* allow group write bit for mkdir */
    

    do_setuid();
    do_setgid();
    DIR *ptrDir;
    int e=0; //err number
    /*if (euidaccess(yeardir,W_OK)==-1) { */
    ptrDir=opendir(monthdir);
    if (ptrDir==NULL) {
        // cant write to yeardir, or doesn't exist 
        e=errno; //get the error
        //printf("Darn: got error e:%d ENOENT:%d\n",e,ENOENT);
        if (e == ENOENT ) { //path doesn't exist, lets create
            if (mkdir(yeardir,mode) != 0) {
                fprintf(stderr,"Error: unable to create directory: %s\n",yeardir);
                fprintf(stderr,"Verify it exists and owned by user:group %s:%s\n",STRINGIFY(DEF_USER),STRINGIFY(DEF_GROUP));
                undo_setuid();
                undo_setgid();
                exit(EXIT_FAILURE);
            }
        }
         else { //cant write to yearpath
                
                fprintf(stderr,"Error: unable to write to directory: %s\n",yeardir);
                fprintf(stderr,"Verify it exists and owned by user:group %s:%s\n",STRINGIFY(DEF_USER),STRINGIFY(DEF_GROUP));

                if (debug) {
                    printf ("set euid: %d\n",euid); //suid user
                    printf ("real ruid: %d\n",ruid); //real user
                }

                undo_setuid();
                undo_setgid();
                exit(EXIT_FAILURE);
        }
    } //end if we can write to yearpath
    if (ptrDir!=NULL) closedir(ptrDir);

    /* verify we can write to monthpath */
    e=0;
    /* if (euidaccess(monthdir,W_OK)==-1) { */
    ptrDir=opendir(monthdir);
    if (ptrDir==NULL) {
        //cant write to monthpath, or doesn't exist...
        e=errno; //get the error
        if (e==ENOENT ) { //path doesn't exist, lets create
            if (mkdir(monthdir,mode) != 0) {
                fprintf(stderr,"Error: unable to create directory: %s\n",monthdir);
                fprintf(stderr,"Verify it exists and owned by user:group %s:%s\n",STRINGIFY(DEF_USER),STRINGIFY(DEF_GROUP));
                undo_setuid();
                undo_setgid();
                exit(EXIT_FAILURE);
            }
        }
        else { //cant write to monthpath
            fprintf(stderr,"Error: unable to write to directory: %s\n",monthdir);
            fprintf(stderr,"Verify it exists and owned by user:group %s:%s\n",STRINGIFY(DEF_USER),STRINGIFY(DEF_GROUP));
            undo_setuid();
            undo_setgid();
            exit(EXIT_FAILURE);
        }
    } //end if we can write to monthpath
    if (ptrDir!=NULL) closedir(ptrDir);

    /* reset the umask */
    umask(old_umask);

    //FileName formatting 
    my_strftime(ldate, sizeof ldate, "%Y.%m.%d-%H:%M:%S.log", localtime(&tvec));
    asprintf(&fname,"%s/slog-%s-%s-%s-%s",monthdir,hname,ruser,upasswd->pw_name,ldate);
    asprintf(&sfname,"slog-%s-%s-%s-%s",hname,ruser,upasswd->pw_name,ldate);
    /* end log name format */


    /* undo setuid only if we want users to be able to read their own files */
    if (allow_user_replay==1) 
        undo_setuid();
        /* this sets the uid to the users uid, not the euid */
        
    fscript = fopen(fname, "w"); //TODO: make this a read/write, and rewind the file when done
    if (fscript == NULL) {
        undo_setuid();
        undo_setgid();
        perror(fname);
        fprintf(stderr,"Verify directory exists and owned by user:group %s:%s\n",STRINGIFY(DEF_USER),STRINGIFY(DEF_GROUP));
        fail();
    }
    /* set read only to user and group */
    if (fchmod(fileno(fscript),0440)!=0)
        fprintf(stderr,"Warning: unable to change permissions on %s\n  Session log may not be secure\n",fname);
    undo_setuid();
    undo_setgid();
    return 1;
}


/* Reads chars from stdin into s, returns length */
int mygetline(char *s, int maxlen)
{
  int c, i, j;

  for(i = 0, j = 0; (c = getchar())!=EOF && c != '\n'; ++i)
  {
    if(i < maxlen - 1)
    {
      s[j++] = c;
    }
  }
  if(c == '\n')
  {
    if(i <= maxlen - 1)
    {
      s[j++] = c;
    }
    ++i;
  }
  s[j] = '\0';
  return i;
}


/* sends log string to remote slog server
    returns num bytes sent, -1 on err  */
int
slogdSend (void *slogMsg, int size) {
    int sent;
    if (slogdIsConnected==1) {
        sent=tlstools_send(session,slogMsg,size); 
        if (sent< 0 ) { /* unable to send message */
            char *errmsg="*** lost connection to sogd server ***";
            write(1, errmsg, strlen(errmsg));
            if (fscript!=NULL) /* are we logging locally? */
              fwrite(errmsg,1,strlen(errmsg),fscript); 
            
            slogdIsConnected=0; /* lost conection to slogd server */
            slogdLostConnection=1;

            /* policy for what happend if we loose connection to slogd server, 
            *  terminate or keep local log to send later */
            if (require_remote_slogd==1 ) {
                printf("\r\n\r\n*** sslogger lost connection to slogd server:%s\r\n", tlstools_client_server);
                printf("\r\nA policy on this host requires sslogger to be connected to a remote slogd server. ");
                printf("If you think you reached this message in error, ask your system administrator to modify the \"require_remote_slogd\" setting in  sslogger.conf\r\n");
                done(); /* quit */
            }
            else if (require_remote_slogd==0 ) {
                errmsg="\r\n*** Sslogger continuing with local logging only\r\n";
                write(1, errmsg, strlen(errmsg));
                if (fscript!=NULL) /*  are logging locally? */
                  fwrite(errmsg,1,strlen(errmsg),fscript);
                
            }
            
        return -1;
        }

        return sent; /* happy return */
    }
    return -1;     
    
    
}

/* slogd connect, returns 1 on succcess 0 on error */
//int 
slogdConnect (char *slogMsg) {
    int err;
    tlstools_client_debug=debug; /* set tlstools client debugging mode */
    memset (&remote_logfile, '\0', sizeof (remote_logfile)); /* clear remote logfile name */
    if (slogd_server==NULL)
        return 0; /* no slogd server is configured */
        
    /* follow tlstoos_c setup here: */
    /* Initialize tls */
    session=(gnutls_session_t)tlstools_init();
    if (session==NULL) {
      fprintf(stderr,"Error: initalizing tlstools\n");
      return 0; /* err out */
    } 

    if (debug > 0) fprintf(stderr,"DEBUG: tls initalized\n");
        
    /* Hello string to send slogd server */
    static char *hi; 
    /* TODO: add version to the below`*/
    asprintf(&hi,"%s%s",header,slogMsg); /* Note slogMsg must end with \n */
    if (debug > 0) fprintf(stderr,"DEBUG: hi=%s\n",hi);
    
    /* Connect to slogd serverr */
    err=tlstools_connect(tlstools_client_server,tlstools_client_serverport,socket_sd,session,hi,remote_logfile,MAX_REMOTE_LOGFILE_LEN); 
    if ( err<0 ) {
        goto end;
    }
    else if (err ==0 ) {
        return 1; /* error in tcp connect */   
    }
    if (debug > 0)
      printf("DEBUG: slogd server returned logfile: %s\n",remote_logfile);
    return 1; /* all is happy */
    
    end:
      tlstools_end_session(socket_sd,session);
      return 1;
}

/*
* script -t prints time delays as floating point numbers
* The example program (scriptreplay) that we provide to handle this
* timing output is a perl script, and does not handle numbers in
* locale format (not even when "use locale;" is added).
* So, since these numbers are not for human consumption, it seems
* easiest to set LC_NUMERIC here.
*/

int
main(int argc, char **argv) {
    /* unset suid bits */
    ruid = getuid ();
    gruid = getgid (); 
    euid = geteuid ();
    geuid = getegid ();
    undo_setuid ();
    undo_setgid();

    extern int optind;
    char *p;
    int ch;
 
    progname = argv[0];
    if ((p = strrchr(progname, '/')) != NULL)
        progname = p+1;


    setlocale(LC_ALL, "");
    setlocale(LC_NUMERIC, "C");	/* see comment above */
    bindtextdomain(PACKAGE, LOCALEDIR);
    textdomain(PACKAGE);

    if (argc == 2) {
        if (!strcmp(argv[1], "-V") || !strcmp(argv[1], "--version")) {
            printf(_("%s (%s)\n"),
                progname, STRINGIFY(VERSION));
            return 0;
        }
    }

    while ((ch = getopt(argc, argv, "c:r:fqthdl")) != -1)
        switch((char)ch) {
        case 'c':
            cflg = optarg;
            break;
        case 'f':
            fflg++;
            break;
        case 'q':
            qflg++;
            break;
        case 't':
            tflg++;
            break;
        case 'h': 
            hflg=0; //default is true, cd to $HOME
            break; 
        case 'd' :
            debug=1;
            break;
        case 'l' :
            log_all_cmds=1;
            break;
        case 'r' : /* reason on cmd line */
            comment=optarg;
            if (debug) printf("DEBUG: reason: %s\n",comment);
            break;
        case '?':
        default:
            fprintf(stderr,
                _("usage: %s [-f] [-q] [-h] [-d] [-l] [-r \"reason\"] [-c command]\n"),progname);
            exit(1);
        }
    argc -= optind;
    argv += optind;
    readConf();
    //Turn on flushing by default
    //fflg++;
       
    tlstools_cert_file=CERT_FILE; /* from tlstools.h */
    tlstools_key_file=KEY_FILE;   /* from tlstools.h */
    tlstools_ca_file=CAFILE;      /* from tlstools.h */

    /* Create local log file directory structure */   
    /* and open fscript for writing */
    if (debug) printf("DEBUG: creating local logfile\n");

    createSlog();    
    if (debug) printf("DEBUG: local logfile createted\n");
    
    getmaster();
    if ((!qflg) && (!cflg) )
        printf(_("Sslogger started, local logfile is %s\n"), fname);
    
    /* Scenario 1: execute a command and quit */
    /* if we get a cmd string, just exec the cmd */
    if (cflg) {
        if (comment==NULL)
         comment="(null)"; /* no comment specfied */
        if  (log_all_cmds==0)  {// do not log cmd output
            if (debug) printf("DEBUG: running execv cmd\n");
            char *shname;
            shname = strrchr(shell, '/'); //split at '/'
            if (shname)
                shname++;
            else {
                shname = shell;
            }

            //close stdin to avoid interactive shells
            fclose(stdin);            
            if (debug) printf("DEBUG: running exec: %s\n",cflg);
            /* Send syslog command */
            char *myCmd;
            asprintf(&myCmd,"invoked_cmd:\"%s\"",cflg);
            //comment below is "(null)" as we don't prompt prompt for a Reason
            if (!logCmd2(ruser,upasswd->pw_name,myCmd,sfname,comment)) {
                /*somting wong, cant open log for writing */
                exit(EXIT_FAILURE);
            }
            /* tell the slogd server no output is comming from command */
            char *slogdMsg="*** sslogger logging of command output disabled on client\r\n";
            slogdSend(slogdMsg,strlen(slogdMsg));

            /* Close the tls session */
            if (slogdIsConnected==1)
              gnutls_bye (session, GNUTLS_SHUT_RDWR);

            /* cd to a users Home dir? */
            if (hflg) {
                if ( (chdir (upasswd->pw_dir)) != 0) {
                    fprintf (stderr,"Warning: cannot change directory to %s\n", upasswd->pw_dir);
                }
            }
              
            usleep(10000);
            execl(shell, shname, "-c", cflg, NULL);
            //we should never get here
            perror(shell);
            exit(EXIT_FAILURE);
        }
        else { //log the output
            if (debug) printf("running popen exec: %s\n",cflg);
            /* Send syslog command */
            char *myCmd;
            asprintf(&myCmd,"invoked_cmd:\"%s\"",cflg);
            
            
            //comment below is "(null)" as we don't prompt prompt for a Reason
            if (!logCmd2(ruser,upasswd->pw_name,myCmd,sfname,comment)) {
                /*somting wong, cant open log for writing */
                exit(EXIT_FAILURE);
            }

            /* cd to a users Home dir? */
            if (hflg) {
                if ( (chdir (upasswd->pw_dir)) != 0) {
                    fprintf (stderr,"Warning: cannot change directory to %s\n", upasswd->pw_dir);
                }
            }

            //close stdin so user cant invoke interactive shell
            fclose (stdin);
                        
            //Do popen here, read the output & set the exit code
            char *cmd2run;
            //asprintf(&cmd2run,"exec %s 2>&1",cflg);
            asprintf(&cmd2run,"%s 2>&1",cflg);
            pinput=popen(cflg,"r");
            if (!pinput)
            {
                fprintf (stderr,
                        "Unable to run command\n");
                        exit(EXIT_FAILURE);
            } 
            usleep(10000);
            //read_from_pipe
            int c;
            while ((c = fgetc (pinput)) != EOF) {
                putchar (c);
                if (c=='\n') { 
			fputc('\r',fscript); //tty kludge
			slogdSend("\r",sizeof(char));
                }
                fputc(c,fscript);
                /* slogd hook to log all outut */
                slogdSend(&c,sizeof(char)); 
            }
            int stat=0;
            int exitVal=0;
            stat=pclose(pinput);
            exitVal=WEXITSTATUS(stat);
            if (debug) fprintf(stderr,"Exit value for popen run cmd %d\n",exitVal);
            usleep(300000); //give other thread chance to read
            if (fscript!=NULL) fclose(fscript);
            
            /* TODO: close slogd client */
            if (slogdIsConnected) //TODO: more to (session!=NULL)  
               gnutls_bye (session, GNUTLS_SHUT_RDWR);
            exit(exitVal);
        }
    }

    /* Scenario 2: run a interactive session */
    if (debug) fprintf(stderr,"DEBUG: running interactive session\n");
    if  (! isatty(fileno(stdout))) {
        perror("TTY required for interactive session\n");
        exit(EXIT_FAILURE);
    }

    if (minCommentSize<1 ) {
        if (debug) fprintf(stderr,"DEBUG: not prompting for comment\n");
        if (comment==NULL) /* no comment on cmd line either */
            comment="(none)";
    }
    else
        {
        if (debug) fprintf(stderr,"DEBUG: prompting for comment\n");
        commentLen=0;
        if (comment==NULL) { /* reason (-r) not passed on cmd line */
          comment=malloc(MAX_HEADER_LEN * sizeof(char)); // allocate mem for the comment
          memset (comment,'\0',MAX_HEADER_LEN); //null out comment
        }
        if (debug) fprintf(stderr,"DEBUG: comment: %s\n",comment);
        if (debug) fprintf(stderr,"DEBUG: comment len: %d\n",strlen(comment));
        while (1 && minCommentSize>0 && strlen(comment)==0 ) { //TODO delete ==NULL ) {
            //if (comment!=NULL) free(comment);
            printf ("\nReason for invoking thus interactive shell for %s:\n",upasswd->pw_name);
            //getline(&comment,&commentLen,stdin);
            commentLen=mygetline(comment,MAX_HEADER_LEN);
            if (debug) printf ("DEBUG: comment len=%d len=%d\n",strlen(comment),commentLen);
            if ( strlen(comment)>minCommentSize) break;
            printf ("Minimum required comment length is: %d\n", minCommentSize);
            memset (comment,'\0',MAX_HEADER_LEN); //null out comment
        }
        fputs("\n",stdout);
        
        commentLen=strlen(comment);
        if (commentLen>0)  //whack off return char
            if (comment[commentLen-1]=='\n') comment[commentLen-1]='\0';

    }

    /* send log messages to syslog & slogd server */
    char *myCmd;
    asprintf(&myCmd,"invoked_shell:\"%s\"",shell);
    if (!logCmd2(ruser,upasswd->pw_name,myCmd,sfname,comment)) {
        /*somting wong, cant open log for writing */
        exit(EXIT_FAILURE);
    }
            
    fflush(fscript);
    fixtty();
   
    if (hflg) {
      if ( (chdir (upasswd->pw_dir)) != 0) {
          fprintf (stderr,"Warning: cannot change directory to %s\n", upasswd->pw_dir);
      }
    }

    (void) signal(SIGCHLD, finish);
    child = fork();
    if (child < 0) {
        perror("fork");
        fail();
    }
    if (child == 0) {
        subchild = child = fork();
        if (child < 0) {
            perror("fork");
            fail();
        }
        if (child) {
            dooutput();
        }
        else {
            doshell();
        }
    } else
        (void) signal(SIGWINCH, resize);
    doinput();

    return 0;
}

/* Restore the effective UID to its original value. */
void
do_setuid (void)
{
    int status;

    // user bits
    #ifdef _POSIX_SAVED_IDS
    status = seteuid (euid);
    #else
    status = setreuid (ruid, euid);
    #endif
    if (status < 0) {
        fprintf (stderr, "Couldn't set uid.\n");
        exit (status);
    }
}

/* Restore the effective GID to its original value. */
void
do_setgid (void)
{
    int status;
    //group bits
    #ifdef _POSIX_SAVED_IDS
    status = setegid (geuid);
    #else
    status = setregid (gruid, geuid);
    #endif
    if (status < 0) {
        fprintf (stderr, "Couldn't set uid.\n");
        exit (status);
    }

    
}

/* Set the effective UID to the real UID. */
void
undo_setuid (void)
{
    int status;
    //user bits
    #ifdef _POSIX_SAVED_IDS
    status = seteuid (ruid);
    #else
    status = setreuid (euid, ruid);
    #endif
    if (status < 0) {
        fprintf (stderr, "Couldn't set uid.\n");
        exit (status);
    }
}

/* Set the effective GID to the real GID. */
void
undo_setgid (void)
{
    int status;
    //group bits
    #ifdef _POSIX_SAVED_IDS
    status = setegid (gruid);
    #else
    status = setregid (geuid, gruid);
    #endif
    if (status < 0) {
        fprintf (stderr, "Couldn't set uid.\n");
        exit (status);
    }

 
}


void
doinput() {
    register int cc;
    char ibuf[BUFSIZ];
    if (fscript!=NULL) 
        (void) fclose(fscript);
    while ((cc = read(0, ibuf, BUFSIZ)) > 0)
        (void) write(master, ibuf, cc);
    done();
}

#include <sys/wait.h>

void
finish(int dummy) {
    int status;
    register int pid;
    register int die = 0;

    register int cc;
    time_t tvec;
    char obuf[BUFSIZ];
    struct timeval tv;
    double oldtime=time(NULL), newtime;
    tvec = time((time_t *)NULL);


    while ((pid = wait3(&status, WNOHANG, NULL)) > 0) {
        if (pid == child) {
            die = 1;
            //printf ("Child signal\n");
            
        }
    }
    if (die)
        done();
}

void
resize(int dummy) {
    /* transmit window change information to the child */
    (void) ioctl(0, TIOCGWINSZ, (char *)&win);
    (void) ioctl(slave, TIOCSWINSZ, (char *)&win);

    kill(child, SIGWINCH);
}

void
dooutput() {
    register int cc;
    time_t tvec;
    char obuf[BUFSIZ];
    struct timeval tv;
    double oldtime=time(NULL), newtime;

    (void) close(0);
#ifdef HAVE_LIBUTIL
     (void) close(slave);
#endif

    tvec = time((time_t *)NULL);
    my_strftime(obuf, sizeof obuf, "%c\r\n", localtime(&tvec));
    fprintf(fscript, _("Sslogger started on %s"), obuf);
    char *slogMsg;
    asprintf(&slogMsg,"Sslogger started on %s", obuf);
    /* send header to slogd server */
    slogdSend(slogMsg,strlen(slogMsg));
    
    for (;;) {
        if (tflg)
            gettimeofday(&tv, NULL);
        cc = read(master, obuf, sizeof (obuf));
        if (cc <= 0)
            break;
        if (tflg) {
            newtime = tv.tv_sec + (double) tv.tv_usec / 1000000;
            fprintf(stderr, "%f %i\n", newtime - oldtime, cc);
            oldtime = newtime;
        }
        /* cc is num of chars read_conf
           obuf is buffer 
        */
        (void) write(1, obuf, cc);
        (void) fwrite(obuf, 1, cc, fscript);
        /* TODO: below wrong place? this is only writng to pty pairs? */
        if (fflg)
            (void) fflush(fscript);

        if (slogdIsConnected==1) slogdSend(&obuf,cc); /* only send data if connected */

        
            }
    done();
}

void
doshell() {
    char *shname;

#if 0
    int t;

    t = open(_PATH_TTY, O_RDWR);
    if (t >= 0) {
        (void) ioctl(t, TIOCNOTTY, (char *)0);
        (void) close(t);
    }
#endif

    getslave();
    (void) close(master);
    if (fscript!=NULL) 
        (void) fclose(fscript);
    (void) dup2(slave, 0);
    (void) dup2(slave, 1);
    (void) dup2(slave, 2);
    (void) close(slave);

    shname = strrchr(shell, '/'); //split at '/'
    if (shname)
        shname++;
    else
        shname = shell;
    usleep(10000);

    /* TODO: slogd hook for header output */
    
    if (debug) printf ("DEBUG: execl %s - %s\n",shell, shname);
    execl(shell, "-",(char *)NULL);
    //we should never get here
    perror(shell);
    fail();
}

void
fixtty() {
    struct termios rtt;
    rtt = tt;
#ifdef __sun__
    rtt.c_cc[VMIN] = 1;
    rtt.c_cc[VTIME] = 1;
    rtt.c_oflag &= ~OPOST;
    //rtt.c_lflag &= ~(ICANON|ISIG|ECHO);
    rtt.c_lflag &= ~(ICANON|ISIG|ECHO|IEXTEN|ECHONL);
    rtt.c_iflag &= ~(INLCR|IGNCR|ICRNL|IUCLC|IXON); 

#else
    /* assume __linux__ */
    cfmakeraw(&rtt);
    rtt.c_lflag &= ~ECHO; 
#endif

    (void) tcsetattr(0, TCSAFLUSH, &rtt);
}

void
fail() {

    (void) kill(0, SIGTERM);
    done();
}

void
done() {
    time_t tvec;
    if (subchild) {
        char buf[BUFSIZ];
        if (!qflg) {
            tvec = time((time_t *)NULL);
            my_strftime(buf, sizeof buf, "%c\r\n", localtime(&tvec));
            fprintf(fscript, _("\nSslogger done on %s"), buf);

        }
        printf ("\r\n");
        /* Close local log file */
        if (fscript!=NULL) { 
            (void) fclose(fscript);
            /* TODO: rewind file here and rewrite*/
        }
        sleep(1);
        if (slogdIsConnected==1) {
            char *slogMsg;
            asprintf(&slogMsg,"\nSslogger done on %s", buf);
            slogdSend(slogMsg,strlen(slogMsg));
            /* Greacefully close the tls slogd connection */
            gnutls_bye (session, GNUTLS_SHUT_RDWR);
            if (keep_local_logs==0) {
                printf ("\r\nSession logs successfully sent to slogd server: %s\r\n",slogd_server);
                printf("Removing local log file: %s\r\n",fname);
                /* TODO: may have to suid to remove */
                unlink(fname);
            }
        }


        (void) close(master);
    } else {
        (void) tcsetattr(0, TCSAFLUSH, &tt);
        if (!qflg)
            if (keep_local_logs==1) printf(_("Sslogger done, local log file is %s\r\n"), fname);
        else printf(_("Sslogger done\r\n"));
        //TODO: REMOVE fclose(fscript); /* TODO: test  close */
        /* TODO: is this where we send slogserver happy end? */
        /* TODO: test close of slogd client, or do we do this in finsh()?*/        
        /*TODO: test remove local log files if log successfuly sent */
        //if (keep_local_logs==0) unlink(fname);
        
        
    }
    exit(0);
}

void
getmaster() {
#ifdef HAVE_LIBUTIL
    (void) tcgetattr(0, &tt);
    (void) ioctl(0, TIOCGWINSZ, (char *)&win);
    if (openpty(&master, &slave, NULL, &tt, &win) < 0) {
        fprintf(stderr, _("openpty failed\n"));
        fail();
    }
#else
    char *pty, *bank, *cp;
    struct stat stb;

    pty = &line[strlen("/dev/ptyp")];
    for (bank = "pqrs"; *bank; bank++) {
        line[strlen("/dev/pty")] = *bank;
        *pty = '0';
        if (stat(line, &stb) < 0)
            break;
        for (cp = "0123456789abcdef"; *cp; cp++) {
            *pty = *cp;
            master = open(line, O_RDWR);
            if (master >= 0) {
                char *tp = &line[strlen("/dev/")];
                int ok;

                /* verify slave side is usable */
                *tp = 't';
                ok = access(line, R_OK|W_OK) == 0;
                *tp = 'p';
                if (ok) {
                    (void) tcgetattr(0, &tt);
                        (void) ioctl(0, TIOCGWINSZ,
                        (char *)&win);
                    return;
                }
                (void) close(master);
            }
        }
    }
    fprintf(stderr, _("Out of pty's\n"));
    fail();
#endif /* not HAVE_LIBUTIL */
}

void
getslave() {
#ifndef HAVE_LIBUTIL
    line[strlen("/dev/")] = 't';
    slave = open(line, O_RDWR);
    if (slave < 0) {
        perror(line);
        fail();
    }
    (void) tcsetattr(slave, TCSAFLUSH, &tt);
    (void) ioctl(slave, TIOCSWINSZ, (char *)&win);
#endif
    (void) setsid();
    (void) ioctl(slave, TIOCSCTTY, 0);
}
