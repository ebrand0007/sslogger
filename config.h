#define VERSION 00.98.14
#define DEBUG 0

/* Default Log Directory */
#ifndef LOG_DIR
#define LOG_DIR /var/log/slog
#endif

/* default log file name */
#ifndef LOGFILE
#define LOGFILE slog.log
#endif


/* ssloger Default config file */
#ifndef CONF_FILE
#define CONF_FILE /etc/sslogger.d/sslogger.conf
#endif

#define STRINGIFY(x) XSTRINGIFY(x)
#define XSTRINGIFY(x) #x

/* The maximum length of a a fully escaped domain name C string. This
* is calculated like this: RFC1034 mandates maximum length of FQDNs
* is 255. The maximum label length is 63. Lets make it 1024 to be safe,
* after all its 2009 and bytes are cheap
*/
#define MAXFQDNLEN 1024

#ifndef MAXHOSTNAMELEN
//TODO: delere #define MAXHOSTNAMELEN 64
#define MAXHOSTNAMELEN MAXFQDNLEN
#endif

/* path to sudo binary */
#ifndef SUDO
//expect sudo to be in default $PATH
#define SUDO sudo
#endif

/* path to sslogger binary */
#ifndef SSLOGGER
#define SSLOGGER sslogger
#endif

////Max size for comments
#define MAXCOMMENTSIZE 100

// Minimum comment size in chars
#define MINCOMMENTSIZE 5

#ifndef DEF_USER
#define DEF_USER slogger
#endif

#ifndef DEF_GROUP
#define DEF_GROUP sloggers
#endif

/* mkdir mode 775 */
#ifndef CREATE_DIR_MODE
#define CREATE_DIR_MODE (S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IXOTH)
#endif

/* SLOGD conf stuff */

#ifndef SYSCONF_DIR
#define SYSCONF_DIR "/etc"
#endif

#ifndef LOCAL_STATE_DIR
#define LOCAL_STATE_DIR "var"
#endif

/* default slogd log file name: LOGDIR/SLOGFNAME */
#ifndef SLOGFILE
#define SLOGFILE slogd.log
#endif

#define SLOGDCONF SYSCONF_DIR "/sslogger.d/sslogger-slogd.conf"
#define SLOGDPIFFIE LOCAL_STATE_DIR "/run/sslogger/sslogger-slogd.pid"
#define SLOG_PKI_DIR SYSCONF_DIR "/pki/slog"
#define SLOG_SERVKEYFILE SLOG_PKI_DIR "/private/serverkey.pem"
#define SLOG_CERTFILE SLOG_PKI_DIR "/servercert.pem"
#define SLOG_CAFILE SLOG_PKI_DIR "/CA/cacert.pem"
//TODO: CRLFILE needs to be signed, so set to ""
#define SLOG_CRLFILE "" /*SLOG_PKI_DIR  "crl.pem" */

#define HEADER_LABEL slogClient:
#define HEADER_LABEL_LEN 11 /* HEADER_LABEL length */
#define MAX_HEADER_LEN 1024 /* Max size of string to be written to log; related to ssloger::MAXCOMMENTSIZE */

#define SA struct sockaddr
#define MAX_BUF 1024 /* buffer size for tls socket reads */
#define PORT 5556       /* listen to 5556 port */
#define DH_BITS 1024 /* number of bits to use in DH encryption */

/* solaris bits: */
#ifndef GROUP_MEMBER_H_
# define GROUP_MEMBER_H_ 1

# include <sys/types.h>

int group_member (gid_t);
#endif /* GROUP_MEMBER_H_ */
