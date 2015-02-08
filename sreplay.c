/* Set terminal (tty) into "raw" mode: no line or other processing done
   Terminal handling documentation:
       curses(3X)  - screen handling library.
       tput(1)     - shell based terminal handling.
       terminfo(4) - SYS V terminal database.
       termcap     - BSD terminal database. Obsoleted by above.
       termio(7I)  - terminal interface (ioctl(2) - I/O control).
       termios(3)  - preferred terminal interface (tc* - terminal control).
       tty_ioctl
*/

#include <termios.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

/*
 *  This file is part of sslogger
 * 
 *  sslogger is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 * 
 *  sslogger is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with sslogger.  If not, see <http://www.gnu.org/licenses/>.
 */


static struct termios orig_termios;  /* TERMinal I/O Structure */
static int fdtty = STDIN_FILENO;     /* STDIN_FILENO is 0 by default */
char up[]="\033[A"; /* Control chars */
char reset[]={0x1b,0x63}; /* Control chars */
int delayReplaySpeed=1200; //delay in replay speed, in microseconds
int defaultReplaySpeed=6000; //default sleep in replay
int maxDelaySpeed=200000; //max delay
int minDelaySpeed=0; //min delay
//int replyStepSpeed=1000; //step speed at which to change replay speed 
unsigned long int fileCharPos=0; //replay file char position
unsigned long int fileLinePos=0; //replay file line number
FILE *pfile; //FH pointer to file to replay
int debug=0;


/* prototypes */
void tty_make_raw(void);
void fail(char *mess);
int tty_restore(void);
void reset_tty(void);
void sreplay_atexit(void);
int replay(void);
int replat2delete(void);
int gotoLine(unsigned long int);
void termination_handler (int); /* signal handler function */


int playSpeed=0;

int main(int argc, char* argv[])
   {
    
    /* trap termination signals && reset tty */
    signal (SIGTERM, termination_handler);
    signal (SIGQUIT, termination_handler);
    signal (SIGHUP, termination_handler);
 
    char *mytty=ttyname(fileno(stdout));
    printf("Sending output to: %s\n",mytty);
    char *filename;
    if ( argc != 2 ) {
      fprintf(stderr, "Usage: %s <filename>\n",argv[0]);
      exit(EXIT_FAILURE);
    }
    //Get args
    filename=argv[1];     
    
    pfile = fopen(filename, "r");
    if (pfile == NULL) {
      perror(filename);
      fail("Could not open file\n");
    }  
    
    
    /* check that input is from a tty */
    if (! isatty(fdtty)) fail("not on a tty");

    /* store current tty settings in orig_termios */
    if (tcgetattr(fdtty,&orig_termios) < 0) fail("can't get tty settings");

    /* register the tty reset with the exit handler */
    if (atexit(sreplay_atexit) != 0) fail("atexit: can't register tty reset");

    tty_make_raw();      
    replay();   
    return 0;       /* sreplay_atexit will restore terminal */
   }

/******************************************************************/
/* exit handler for tty reset */
void sreplay_atexit(void)  /* NOTE: If the program terminates due to a signal   */
{                          /* this code will not runi, must use signal handler  */
  tty_restore();        
  reset_tty();
}                     


/******************************************************************/
void termination_handler (int signum)  { /* signal handler function */
switch(signum){
    if (debug>0) printf("Enter Signal termination_handler\n");
    case SIGHUP:
        /* reset terminal */
        sreplay_atexit();
        break;
    case SIGTERM:
        /* reset terminal */
        sreplay_atexit();
        break;
    case SIGQUIT:
        /* reset terminal */
        sreplay_atexit();
        break;
    case SIGINT:
        /* reset terminal */
        sreplay_atexit();
        break;
    }
    if (debug >0) printf("Exit Signal termination_handler\n");
    exit(0);
}
/******************************************************************/
/* Fatal error handler */
void fail(char *message)
{
  fprintf(stderr,"Error: %s\n",message);
  exit(1);
}

/******************************************************************/
/* Set the tty in raw mode */
void tty_make_raw(void)
{
  struct termios rawtty;
  
  rawtty = orig_termios;  /* copy original and then modify below */

  /* input modes - clear indicated ones giving: no break, no CR to NL, 
   *       no parity check, no strip char, no start/stop output (sic) control */
  rawtty.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
  
  /* output modes - clear giving: no post processing such as NL to CR+NL */
  rawtty.c_oflag &= ~(OPOST);
  
  /* control modes - set 8 bit chars */
  rawtty.c_cflag |= (CS8);
  
  /* local modes - clear giving: echoing off, canonical off (no erase with 
   *       backspace, ^U,...),  no extended functions, no signal chars (^Z,^C) */
  rawtty.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
  
  /* control chars - set return condition: min number of bytes and timer */
  //rawtty.c_cc[VMIN] = 5; rawtty.c_cc[VTIME] = 8; /* after 5 bytes or .8 seconds */
  /*  after first byte seen      */
  rawtty.c_cc[VMIN] = 0; rawtty.c_cc[VTIME] = 0; /* immediate - anything       */
  //rawtty.c_cc[VMIN] = 2; rawtty.c_cc[VTIME] = 0; /* after two bytes, no timer  */
  //rawtty.c_cc[VMIN] = 0; rawtty.c_cc[VTIME] = 8; /* after a byte or .8 seconds */

  /* put terminal in raw mode after flushing */
  if (tcsetattr(fdtty,TCSAFLUSH,&rawtty) < 0) fail("can't set raw mode");                                             
}

/******************************************************************/
/* Send reset to the TTY */
void reset_tty (void) {
  //reset terminal
  write (fdtty,&reset,2);
}

/******************************************************************/
/* restore tty to original tty settings */
int tty_restore(void)
   {
    /* flush and reset */
    if (tcsetattr(fdtty,TCSAFLUSH,&orig_termios) < 0) return -1;
    sleep(1); 
    return 0;
   }

/******************************************************************/
int help (void) {
  //reset terminal
  reset_tty();
  
  printf ("\r\n\r\nPress the following keys during the replay session:\r\n");   
  printf ("    f or /    Find a string (not implemented yet)\r\n");
  printf ("    n or /    Find the next match (not yet implemented)\r\n");
  printf ("    r or ?    Find backwards (not implemented yet)\r\n");
  printf ("    b         Back up 1 line\r\n");
  printf ("    <enter>   Display next line\r\n");
  printf ("    <anykey>  Display next char\r\n");
  printf ("    q         quit\r\n");
  printf ("    + or p    Starts auto-replay\r\n");
  printf ("    d         Toggle debug mode\r\n");
  printf ("\r\n");
  printf ("During playback:\r\n");
  printf ("    +         Increase playback speed\r\n");
  printf ("    -         Decrease playback speed\r\n");
  printf ("    <anykey>  End auto-replay \r\n");
  sleep(2);
  int c,answer;
  c=-1;
  while (c<1) {
    c=fgetc(stdin);
    answer=tolower(c);
    usleep(500);
  }
  
  return 1;
}
 
 /******************************************************************/
 int busy_wait(int u_seconds)
 {
   struct timeval start, end;
   gettimeofday(&start, NULL);
   long int start_usec=start.tv_usec;
   start_usec+=u_seconds;  //add the sleep time
   if (start_usec > 999999999) { //roll over the usec
      start.tv_sec++;
      start_usec-=999999999;
      start.tv_usec=start_usec;
   }
   while (1) {
     gettimeofday(&end, NULL);
     //if(start.tv_usec != end.tv_usec)
     if (start.tv_sec<end.tv_sec)
       break;
     else if(start_usec < end.tv_usec)
       break;
     sched_yield(); //yield some cpu time to other processes
   }
   //printf("\r\nStart =%06d:%07d, End =%07d:%07d\r\n",start.tv_sec, (int)start.tv_usec, end.tv_sec,(long)end.tv_usec);
   return 0;
 }
 /******************************************************************/
 void endOFile (void) {
   printf("\r\n\r\n<End of sreplay file>\r\n");
   //printf("charPos:%d lineNum:%d\r\n",fileCharPos,fileLinePos );
 }
 /******************************************************************/
 void my_usleep(unsigned long milliseconds)
 {
   /* issue usleeping <5000 ms on x86 */
   struct timespec tmReq;
   tmReq.tv_sec = (time_t)0;
   tmReq.tv_nsec = milliseconds;
   // we're not interested in remaining time nor in return value
   (void)nanosleep(&tmReq, (struct timespec *)NULL);
 }
 
 
 /******************************************************************/
 int gotoLine(unsigned long int seekTo) {
   int retVal=1;
   rewind(pfile); //set file pointer to the beginiinig
   //reset terminal
   reset_tty();
   fileCharPos=0;
   fileLinePos=0;
   //printf("seekTo: %d filecharPos:%d fileLinePos:%d\r\n",seekTo,fileCharPos,fileLinePos);
   while (fileLinePos<seekTo && retVal>0) {
     retVal=printNextLine();
     //printf("seekTo: %d filecharPos:%d fileLinePos:%d\r\n",seekTo,fileCharPos,fileLinePos);
     //sleep(1);
   }
   
   return 1; 
 }
 
 /******************************************************************/
 int gotoPos (unsigned long int pos) {
   int retVal=1;
   rewind(pfile); //set file pointer to the beginiinig
   reset_tty();
   fileCharPos=0;
   fileLinePos=0;
   while (fileCharPos<pos && retVal>0) {
     retVal=printNextChar();
   }
   //printf("filecharPos:%d pos:%d\r\n",fileCharPos,pos);
   return 1; 
 } 
 
/******************************************************************/   
int replay() 
{
  /* start loop  for cmd chars to run */
  int forever=1;
  char cmd;
  int bytesread=0;
  while (forever>0) { 
    /* don't do anything till we getc a char */
    bytesread=read(fdtty, &cmd, 1); /* read up to 1 byte */
    if (bytesread <0 ) fail("reading chars from tty");
    if (bytesread > 0) { //we have a char presses
            if (cmd=='q' || cmd=='Q' || cmd==3 ) {
              printf ("\r\nQuitting on user command\r\n");
              usleep(500);
              tcflush(STDIN_FILENO, TCIOFLUSH); /*clear tty buffer */
              break; // quit
            }
            else if (cmd==13) forever=printNextLine(); //-1 returned on eof
            else if (cmd=='+' || cmd=='p' || cmd=='P') forever=replayAtSpeed(defaultReplaySpeed); //-1 returned on eof
            else if (cmd=='b' || cmd=='B' ) {
              if (fileLinePos<2) {
                gotoLine(1);
              }
              else gotoLine(fileLinePos-2);
            }
            else if (cmd=='h') { 
              help();
              gotoPos(fileCharPos); 
            }
            else if (cmd=='d') {
               if (debug==0) debug=1;
               else debug=0;
            }
            /* else aother key was pressed,so print next char */
            else forever=printNextChar(); //-1 returns on eof
            cmd='\0';
    }
    my_usleep(500*1000);
  }
  
}

/******************************************************************/
int replayAtSpeed (int speed) {
  // replays file at speed: speed
  // returns -1 on EOF or quit
  // returns 1 on char press
  delayReplaySpeed=speed;
  int ch;
  int bytesread;
  while ((ch =fgetc(pfile))!=EOF) {
    //printf("Blocking tty read\n");
    char cmd;
    /*tty way */
    char a;
    a=toascii(ch);
    write(fdtty,&a,1); //print the char
    fileCharPos++; //increase the char position
    if (ch==13) { 
      fileLinePos++; //increase the line number 
    }
    if (debug>0) {
      printf ("\r\nREPLAYATAPWEED delayReplaySpeed=%d cmd=%d\n",delayReplaySpeed,cmd);
    }
    bytesread=0;
    bytesread = read(fdtty, &cmd, 1 /* read up to 1 byte */);
    if (bytesread>0) {

      if (cmd=='+') delayReplaySpeed=delayReplaySpeed/2; //double the play speed
      else if (cmd=='-') delayReplaySpeed=delayReplaySpeed*2; //cut the speed in half 
      else if (cmd=='q' || cmd=='Q' || cmd==3 ) {
        printf("\r\nQuitting on user command\r\n");
        return -1;
      }
      else if (cmd=='d') {
        if (debug==0) debug=1;
        else debug=0;
      }
#ifdef __linux__
      else if (cmd==27) {
        /* linux tty bug?? 
         * flush the in buffer, print the esc char, and continue */
        tcflush(STDIN_FILENO, TCIOFLUSH);
        a=toascii(ch);
        write(fdtty,&a,1); //print the char
        fileCharPos++; //increase the char position
        continue; 
      }
#endif
      else {
        if (debug>0) printf("\r\nExiting replayAtSpeeds. bytesread=%d cmd=%d\r\n",bytesread,(int)cmd);
        return 1; //pause    
      }
      if (delayReplaySpeed<minDelaySpeed) delayReplaySpeed=minDelaySpeed;
      if (delayReplaySpeed>maxDelaySpeed) delayReplaySpeed=maxDelaySpeed;
      if (debug>0)  {
          printf("\r\nSetting replay speed to:%d\r\n",delayReplaySpeed);
          sleep(1);
      }
    }
    if  (delayReplaySpeed > 999 ) my_usleep(delayReplaySpeed*1000); //min nanosleep on RHEL5
       else if (delayReplaySpeed > 1) busy_wait(delayReplaySpeed); //use busywait instead
  }
  endOFile();
  return 1; //1;
  
}



/******************************************************************/
int printNextLine() {
  // displays the next full line of text from the replay file
  // returns -1 on EOF
  int ch;
  while ((ch =fgetc(pfile))!=EOF) {
    /*tty way */
    char a;
    a=toascii(ch);
    write(fdtty,&a,1); //print the char
    fileCharPos++; //increase the char position
    if (ch==13) { 
      fileLinePos++; //increase the line number
      return 1;
    }
  }
  endOFile();
  return 1; //-1; //Assume we hit EOF
}

/******************************************************************/  
int printNextChar() {
  // Displays the next char from the replay file
  // returns -1 on EOF
  int ch;
  if ((ch =fgetc(pfile))==EOF) {
    endOFile();
    return 1; //eof hit
  }
  fileCharPos++; //increase the char position
  if (ch==13) fileLinePos++; //increase the line number
    /*tty way */
    char a;
  a=toascii(ch);
  
  
  write(STDOUT_FILENO,&a,1);
  
  if (!(isalnum(ch))) printNextChar(); //skip control chars, and others
    //if (iscntrl(ch)) printNextChar(); // also get next char if control char
  return 1;
}

/******************************************************************/

