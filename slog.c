#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include "config.h"

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

//prototypes
char * shiftArgv(int argc, char **argv);
void usage(void);
//max cmd line length
#define MAXCMDLEN 1024

//global vars
char *progname="slog";
int debug=0;

void usage(void) {
    fprintf(stderr, "Usage: %s [-u <user>] [-d] [-h] [-f] [cmd and args]\n",progname);
    fprintf(stderr,"    -u <user>\tAttempt to run as <user>\n");
    fprintf(stderr,"    -d\t\tDebug\n");
    fprintf(stderr,"    -h\t\tDo not switch to <user> home directory. Remain in current working directory\n");
    fprintf(stderr,"    -f\t\tFlush output after every line\n");
    fprintf(stderr,"    \"command and args\"\n");
    fprintf(stderr,"    \t\tExecute \"command and args\" instead if interactive shell.\n");
    fprintf(stderr,"    \t\tNon-interactive mode. Provides ability run sslogger within  a script\n");
    exit(EXIT_FAILURE);
}


int main(int argc, char* argv[]) {
    int x=0;
    const int maxSudoOpts=6;
    char *sudoOpts[maxSudoOpts];
    sudoOpts[0]=STRINGIFY(SUDO); //from config.h
    sudoOpts[1]="-u";
    sudoOpts[2]="root"; //default sudo user
    sudoOpts[3]="-H"; //set the user $HOME
    sudoOpts[4]=(char*)0; // terminate list
    char **p_sudoOpts; //alternate pointer to sudoOpts
    p_sudoOpts=&sudoOpts[3]; //point to end of array  

    char *sloggerOpts[argc+4]; //need 2 quotes and null terminator
    sloggerOpts[0]=STRINGIFY(SSLOGGER); //from config.h"slogger";
    sloggerOpts[1]=NULL; //terminate list
    char **p_sloggerOpts; //alternate pointer to sloggerOpts
    p_sloggerOpts=&sloggerOpts[1]; //point to end of array
    char slCmd[MAXCMDLEN];  //quoted command to send to ssloger -c 
    slCmd[0]='\0'; //empty string

    if (argc>1 && (!strcmp(argv[1], "-V") || !strcmp(argv[1], "--version"))) {
        printf("%s (%s)\n",progname, STRINGIFY(VERSION));
        exit(EXIT_SUCCESS);
        }

    if (argc>1 && (!strcmp(argv[1], "-V") || !strcmp(argv[1], "--help"))) {
        usage();
        exit(EXIT_SUCCESS);
    }

    x=1;
    if (argc>1) {
        argv++; //parse args, skipping progname
     }
    while (argv!=NULL && x<argc) { //parse args
      /* couldn't use getopts, as we need to pass unknown args to slogger as -c $args */
      //if (x>=argc) break;
      if (strcmp(*argv,"-d")==0) { //enable debugging 
          debug=1;
          *p_sloggerOpts="-d";
          p_sloggerOpts++;
          *p_sloggerOpts=NULL; //terminate the list
       }
      else
      if (strcmp(*argv,"-r")==0) { //reason is on cmd line
          *p_sloggerOpts="-r";
          p_sloggerOpts++;
          argv++; /* increment argv pointer */
          x++; /* increment argument count */
          if (argv==NULL || x==argc) usage();
          *p_sloggerOpts=*argv; /* argv pointer is the "reason" */
          p_sloggerOpts++;
          *p_sloggerOpts=NULL; //terminate the list
       }
      else
      if (strcmp(*argv,"-h")==0) {
          // don't cd $HOME for new user
          *p_sloggerOpts="-h";
          p_sloggerOpts++;
          *p_sloggerOpts=NULL; //terminate the list
      }
      
      else if (strcmp(*argv,"-f")==0) {
          *p_sloggerOpts="-f";
          p_sloggerOpts++;
          *p_sloggerOpts=NULL; //terminate the list
      }
       
      else if (strcmp(*argv,"-u")==0) {
           /* set the sudo user */ 
           if (*(argv+1)==NULL) usage();
           sudoOpts[2]=*(argv+1);
           argv++;
           x++;
      }
      else {
          *p_sloggerOpts="-c";
          p_sloggerOpts++;
          if (*(argv)[0] == '-' || x==argc) { //Make sure -c has additional args, and firs arg doesn't start with '-'
            usage();
            exit(EXIT_FAILURE); 
          }
          /* loop trough remaining args, adding all to p_sloggerOpts */
          while (argv!=NULL && x<argc) {
              strcat(slCmd,*(argv));
              argv++;
              x++;
              if (x<argc)
                  strcat(slCmd," ");
          }
          *p_sloggerOpts=&slCmd[0];
          p_sloggerOpts++;
          *p_sloggerOpts=NULL;
          break; 
      }
      argv++;
      x++;
    }

    if (debug) { 
        //print sudo opts
        p_sudoOpts=&sudoOpts[0]; //point to beginning of array
	printf("sudo Opts:");
        while (*p_sudoOpts!=NULL) {
            printf("%s ",*p_sudoOpts);
            *p_sudoOpts++;
        }
        printf("\n");
        //print slogger opts
        printf("sloggerOpts:");
        p_sloggerOpts=&sloggerOpts[0];
        while (*p_sloggerOpts!=NULL) {
            printf("%s ",*p_sloggerOpts);
            *p_sloggerOpts++;
        }
        printf("\n");
        printf("slCmd:%s\n",slCmd);
    }

    /* join p_sudoOpts and p_sloggerOpts */
    int sudoOptsCount=0;
    int sloggerOptsCount=0;

    p_sudoOpts=&sudoOpts[0]; //point to beginning of array
    while (*p_sudoOpts!=NULL) {
	sudoOptsCount++;
        *p_sudoOpts++;           
    }
    p_sloggerOpts=&sloggerOpts[0]; //point to beginning of array
    while (*p_sloggerOpts!=NULL) {
	sloggerOptsCount++;
        *p_sloggerOpts++;
    }
    int optTot=sudoOptsCount+sloggerOptsCount+1;
    if (debug) printf ("OptTot=%d\n",optTot);
    char *cmd[optTot];
    char **p_cmd; //ptr to cmd list
    p_cmd=&cmd[0];
    p_sudoOpts=&sudoOpts[0]; //point to beginning of array
    while (*p_sudoOpts!=NULL) {
        *p_cmd=*(p_sudoOpts);
        *p_cmd++;
	*p_sudoOpts++;
    }
    p_sloggerOpts=&sloggerOpts[0]; //point to beginning of array
    while (*p_sloggerOpts!=NULL) {
        *p_cmd=*(p_sloggerOpts);
        //printf ("string:%s\n",*p_cmd);
        *p_cmd++;
	*p_sloggerOpts++;
    }   
    *p_cmd=NULL; //terminate the array
    

    if (debug) {
	// print the cmd array now
	p_cmd=&cmd[0];
	while (*p_cmd!=NULL) {
	    printf("%s ",*p_cmd);
	    *p_cmd++;
	}
	printf ("\n");
    }
    if ( execvp(cmd[0],cmd)<0) {
	//TODO: error trapping of return vals
	printf("Exec went bad\n");
	exit(EXIT_FAILURE);
    }


return 0; 
}
