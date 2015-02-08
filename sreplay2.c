#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <printf.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <time.h>
#include <ctype.h>
#include <sched.h>
#include <sys/time.h>

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

#define TTY_BUFSIZE     1024

//prototypes
int replay (const char *, const char *);
int help (void);
int myrestore_tty(void);
int printNextChar(void);
int printNextLine(void);
int findForward (void);
char * readLine(FILE *);
int findNext (fpos_t *, char *);
//int tty_get_state(struct termios *, int);
//int tty_set_state(struct termios *, int); 

struct termio tty_saved, tty_current; //man 3 termios
// static char		*in_buff,	/* line input/output buffers	*/
// 			*out_buff,
// 			*in_ptr,
// 			*out_ptr;
// static int		in_size,	/* buffer sizes and counters	*/
// 			out_size,
// 			in_cnt,
// 			out_cnt;
// int opt_v=0; //1 for debuggin
int fdtty; //fd of tty
int fdtty_r; //fd read of tty
int isrestored=0; //set to one when tty is restored
int delayReplaySpeed=1200; //delay in replay speed, in microseconds
int defaultReplaySpeed=6000; //default sleep in replay
int maxDelaySpeed=200000; //max delay
int minDelaySpeed=0; //min delay
//int replyStepSpeed=1000; //step speed at which to change replay speed 
unsigned long int fileCharPos=0; //replay file char position
unsigned long int posInLine=0; //position in current line
unsigned long int fileLineNum=0; //replay file line number
FILE *pfile; //FH pointer to file to replay
//TODO: get/set window size
//man tty_ioctl 


int playSpeed=0;
/******************************************************************/
int help (void) {
    //reset terminal
    char a=0x1b;
    char b=0x63;
    write(fdtty,&a,1);
    write(fdtty,&b,1);
    
    printf ("\r\n\r\nPress the following keys during the replay session:\r\n");   
    printf ("    f or /    Find a string (not implemented yet)\r\n");
    printf ("    n or /    Find the next match (not yet implemented)\r\n");
    printf ("    r or ?    Find backwards (not implemented yet)\r\n");
    printf ("    b         Back up 1 line\r\n");
    printf ("    <enter>   Display next line\r\n");
    printf ("    <anykey>  Display next char\r\n");
    printf ("    q         quit\r\n");
    printf ("    + or p    Starts auto-replay\r\n");
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
    //printf("charPos:%d lineNum:%d\r\n",fileCharPos,fileLineNum );
}
/******************************************************************/
void my_usleep(unsigned long milliseconds)
{
    struct timespec tmReq;
    tmReq.tv_sec = (time_t)0;
    tmReq.tv_nsec = milliseconds;
    // we're not interested in remaining time nor in return value
    (void)nanosleep(&tmReq, (struct timespec *)NULL);
}


/******************************************************************/
int gotoLine(unsigned long int seekTo) {
       if (seekTo < 1) return 0;
       int retVal=1;
       rewind(pfile); //set file pointer to the beginiinig
       //reset terminal
       char a=0x1b;
       char b=0x63;
       write(fdtty,&a,1);
       write(fdtty,&b,1);
       fileCharPos=0;
       fileLineNum=0;
       while (fileLineNum<seekTo && retVal>0) {
           retVal=printNextLine();
       }
       //printf("filecharPos:%d fileLinepos:%d\r\n",fileCharPos,fileLineNum);
       return 1; 
}
/******************************************************************/
int gotoPos (unsigned long int pos) {
       int retVal=1;
       rewind(pfile); //set file pointer to the beginiinig
       //reset terminal
       char a=0x1b;
       char b=0x63;
       write(fdtty,&a,1);
       write(fdtty,&b,1);
       fileCharPos=0;
       fileLineNum=0;
       posInLine=0;
       while (fileCharPos<pos && retVal>0) {
           retVal=printNextChar();
       }
       //printf("filecharPos:%d pos:%d\r\n",fileCharPos,pos);
       return 1; 
}
/******************************************************************/
/******************************************************************/
/******************************************************************/
int replayAtSpeed (int speed) {
    // replays file at speed: speed
    // returns -1 on EOF or quit
    // returns 1 on char press
    delayReplaySpeed=speed;
    int ch;
    while ((ch =fgetc(pfile))!=EOF) {
        int cmd=0;
        /*tty way */
        char a;
        a=toascii(ch);
        write(fdtty,&a,1); //print the char
        fileCharPos++; //increase the char position
        posInLine++; //increment the  current position in the line
        if (ch==13) { 
            fileLineNum++; //increase the line number 
            posInLine==0; //reset position in line back to the start
        }
       cmd=getc(stdin);
       if (cmd>0) {
          if (cmd=='+') delayReplaySpeed=delayReplaySpeed/2; //double the play speed
          else if (cmd=='-') delayReplaySpeed=delayReplaySpeed*2; //cut the speed in half 
          else if (cmd=='q' || cmd=='Q' || cmd==3 ) {
              printf("\r\nQuitting on user command\r\n");
              return -1;
              }
          else return 1; //pause    
          if (delayReplaySpeed<minDelaySpeed) delayReplaySpeed=minDelaySpeed;
          if (delayReplaySpeed>maxDelaySpeed) delayReplaySpeed=maxDelaySpeed;
          //printf("\r\nSeting replay speed to:%d\r\n",delayReplaySpeed);
          //sleep(1);
       }
       cmd=0;
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
        posInLine++; //increment the  current position in the line
        if (ch==13) { 
            fileLineNum++; //increase the line number
            posInLine=0; //reset position in line back to the start
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
    posInLine++;
    if (ch==13) { 
        fileLineNum++; //increase the line number
        posInLine=0; //reset position in line back to the start
    }
    /*tty way */
    char a;
    a=toascii(ch);
    write(fdtty,&a,1);
    if (!(isalnum(ch))) printNextChar(); //skip control chars, and others
    //if (iscntrl(ch)) printNextChar(); // also get next char if control char
    return 1;
}
/******************************************************************/
int replay(const char *name, const char *tty) {
  
    pfile = fopen(name, "r");
    if (pfile == NULL) {
        perror(name);
        return -1;
    }
    
    if ( (fdtty=open(tty,O_WRONLY , 0666))  < 0 ) {
        printf ("unable to open tty: %s for writing\n",tty);
        return -1;
    }
  
    if ( (fdtty_r=open(tty,O_RDONLY , 0666))  < 0 ) {
        printf ("unable to open tty: %s for writing\n",tty);
        return -1;
    }
  
  /* Fetch the current state of the terminal. */
    if (tty_get_state(&tty_saved, fdtty) < 0) {
        fprintf(stderr, "Error: tty_open: cannot get current state!\n");
        return -1;
    }
    usleep(5000);
    //SET TERMINAL TO DISABLE RAW ECHO:
    tty_current.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP
                    | INLCR | IGNCR | ICRNL | IXON);
    tty_current.c_oflag &= ~OPOST;
    tty_current.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    tty_current.c_cflag &= ~(CSIZE | PARENB);
    tty_current.c_cflag |= CS8;
  
    if (tty_set_state(&tty_current, fdtty) < 0) {
        fprintf(stderr, "Error: tty_open: cannot set tty state!\n");
       return -1;
    }
    
    /* start loop  for cmd chars to run */
    int forever=1;
    tcflush(fdtty, TCIOFLUSH);
    while (forever>0) { 
        /* don't do anything till we getc a char */
        int cmd=getc(stdin);
        if (cmd > 0) { //we have a char presses
            if (cmd=='q' || cmd=='Q' || cmd==3 ) {
                printf ("\r\nQuitting on user command\r\n");
                usleep(500);
                tcflush(fdtty, TCIOFLUSH);
                break; // quit
            }
            else if (cmd==13) forever=printNextLine(); //-1 returned on eof
            else if (cmd=='/' || cmd=='f' ) findForward();
            else if (cmd=='+' || cmd=='p' || cmd=='P') forever=replayAtSpeed(defaultReplaySpeed); //-1 returned on eof
            else if (cmd=='b' || cmd=='B' ) gotoLine(fileLineNum-2);
            else if (cmd=='h') { 
                help();
                gotoPos(fileCharPos); //TODO: use gotoPos
            }
            //a char was press, print next char
            else forever=printNextChar(); //-1 returned on eof
            
            
            cmd=-1;
        }
        my_usleep(500*1000);
    }
    sleep(1);
    //RESET THE TTY
    myrestore_tty();
    fclose (pfile);
    close(fdtty);
    close(fdtty_r);
    return 0;    
}

/******************************************************************/
int myrestore_tty(void) {
  usleep(1000);
  if (isrestored==1) {
      //printf ("\rAlready restored\n");
      return 1;
  }
  //printf ("\r\nRestoring Console Settings\n");
  

  //reset the tty to the previous state
  sleep (1);
  tty_set_state(&tty_saved, fdtty);

  //flush tty buffers
  int bytesInBuffer;
  (void) ioctl(fdtty_r, FIONREAD, &bytesInBuffer );
  //printf ("\nThere are %d bytes left in the buffer, flushing\n",bytesInBuffer);
  //tcflush(fdtty, TCIOFLUSH);
  isrestored=1;
  
  char a=0x1b;
  char b=0x63;
  write(fdtty,&a,1);
  write(fdtty,&b,1);
  usleep(1500);
  return 1;
  
}

/******************************************************************/
/* Fetch the state of a terminal. */
int tty_get_state(struct termios *tty, int tty_fd)
{
  if (ioctl(tty_fd, TCGETA, tty) < 0) {
	//fprintf(stderr, "dip: tty_get_state: %s\n", strerror(errno));
	return(-1);
  }
  return(0);
}

/******************************************************************/
int tty_set_state(struct termios *tty, int tty_fd)
{
  if (ioctl(tty_fd, TCSETA, tty) < 0) {
	//fprintf(stderr, "dip: tty_set_state: %s\n", strerror(errno));
	fprintf(stderr, "tty_set_state\n");
	return(-1);
  }
  //tcdain(tty_fd);
  return(0);
}

/******************************************************************/

int
findReverse (void) {
  /* TODO: */
    /*
    store our current position (fileCharPos
    rewind the file
    serch for striug (find forward?)
      thisMatch=findNext(0,searchString) //returns -1 on not found
      //TODO this means findForward must return the position, not just doit
      if thisMatch<0, not found
    found? 
       if thisMach > fileCharPos - not found, error out : repteat
      else
        lastMatch=thisMatch;
          thisMatch=findForward
          if thisMatch > fileCharPos {use lastMatch}
          else
          {
             thisMatch=lastMach
             :repeat
          } 
          
  /* fileCharPos is current file pos
     fileLineNum is current Line number in file
     int ff_lineNum is the line number movinf foreard where the string is found, init to fileLineNum
     int ff_linePos is the posistion in the line where the string is found, initially set to posInLine
         need to add posInLine to the printNextChar sub, it is the current pos in the current line     
     //Start at fileCharPos
     */
     unsigned long int ff_lineNum=fileLineNum;  //set to the file line number where the string is found
     //TODO: delete: unsigned long int ff_LinePos=PosInLine //set to the position in the line where the strng is  found
     unsigned long int ff_fileCharPos=fileCharPos; //On success, set to the string position in the file if the string is found.
     char *position; //local
     char *line =(char*) calloc(0, sizeof(char) ); 
     char *searchString="booger";
     char ch;
     fpos_t t_position;
     fgetpos(pfile, &t_position); //backup current file position
     while (feof(pfile)==0) {
        int len=0;
        while ( (ch = fgetc(pfile) ) != EOF && ch != '\n') { //Read remainder of this Line into line
            line = (char*) realloc(line, sizeof(char) * (len + 2) );
            line[len++] = ch;
            line[len] = '\0';
            ff_fileCharPos++; // keep track of where we are in the file
            position=strstr(line,searchString);
            if (position==NULL) { //string not found

                continue; //not found yet
            }
            else { //we found a match
                /* rewind the file to fileCharPos */
                //printf ("foundString. pos=%d",ff_fileCharPos);
                fsetpos(pfile,&t_position); //set file piinter to where we started
                gotoPos(ff_fileCharPos+1); //TODO: + strinlen(searchString)? or index offset?
                return 1; //happy find

            }             
        } //end while 
        //printf("reading next line\n");
     } //end while not eof
     // reset file pointer to where we startes
     fsetpos(pfile,&t_position);
     return 0; // string not found
     //TODO: wrap around to begininnig of file
 }

/******************************************************************/

int
findForward (void) {
  /* TODO: retutn -1 on not found, pos at end of string if found. parameters startAt, and searchStrng */
  /* fileCharPos is current file pos
     fileLineNum is current Line number in file
     int ff_lineNum is the line number movinf foreard where the string is found, init to fileLineNum
     int ff_linePos is the posistion in the line where the string is found, initially set to posInLine
         need to add posInLine to the printNextChar sub, it is the current pos in the current line     
     //Start at fileCharPos
     */
     unsigned long int ff_lineNum=fileLineNum;  //set to the file line number where the string is found
     //TODO: delete: unsigned long int ff_LinePos=PosInLine //set to the position in the line where the strng is  found
     unsigned long int ff_fileCharPos=fileCharPos; //On success, set to the string position in the file if the string is found.
     char *position; //local
     char *line =(char*) calloc(0, sizeof(char) ); 
     char *searchString="booger";
     char ch;
     fpos_t t_position;
     fgetpos(pfile, &t_position); //backup current file position
     while (feof(pfile)==0) {
        int len=0;
        while ( (ch = fgetc(pfile) ) != EOF && ch != '\n') { //Read remainder of this Line into line
            line = (char*) realloc(line, sizeof(char) * (len + 2) );
            line[len++] = ch;
            line[len] = '\0';
            ff_fileCharPos++; // keep track of where we are in the file
            position=strstr(line,searchString);
            if (position==NULL) { //string not found

                continue; //not found yet
            }
            else { //we found a match
                /* rewind the file to fileCharPos */
                //printf ("foundString. pos=%d",ff_fileCharPos);
                fsetpos(pfile,&t_position); //set file piinter to where we started
                gotoPos(ff_fileCharPos+1);  //TODO: + strinlen(searchString)? or index offset?
                return 1; //happy find

            }             
        } //end while 
        //printf("reading next line\n");
     } //end while not eof
     // reset file pointer to where we startes
     fsetpos(pfile,&t_position);
     return 0; // string not found
     //TODO: wrap around to begininnig of file
 }
 
/******************************************************************/
int
findNext (fpos_t *t_position, char *searchString) {
     fpos_t t_currentPos;
     fgetpos(pfile,&t_currentPos); /* backup current position */
     fsetpos(pfile,t_position); /* seek to startAt */     
     char ch;
     char *position; 
     char *line =(char*) calloc(0, sizeof(char) ); 
     while (feof(pfile)==0) {
        int len=0;
        while ( (ch = fgetc(pfile) ) != EOF && ch != '\n') { //Read remainder of this Line into line
            line = (char*) realloc(line, sizeof(char) * (len + 2) );
            line[len++] = ch;
            line[len] = '\0';
            position=strstr(line,searchString);
            if (position==NULL) { //string not found

                continue; //not found yet
            }
            else { //we found a match
                /* rewind the file to fileCharPos */
                //printf ("foundString. pos=%d",ff_fileCharPos);
                fgetpos(pfile,t_position); /* get the current position  */
                fsetpos(pfile,&t_currentPos); //set file piinter to where we started
                return (1); //happy find

            }             
        } //end while 
        //printf("reading next line\n");
     } //end while not eof


    return -1; // not found
}
/******************************************************************/

     
  /*   
  char *find_haystack = "http://www.iota-six.co.uk";
  char *search_string = "iota-six";
  char *position;
  int index;

  position = strstr(find_haystack, search_string);

  if(position==NULL) {
    printf("%s not found in %s\n", search_string, find_haystack);
  }
  else {
    printf("Address of find_haystack: 0x%p\n", find_haystack);
    printf("Address of position: 0x%p\n", position);

    index = find_haystack - position; //pointer arithmetic! 


    if(index<0) {
      index = -index;       // take the positive value of index //
    }

    printf("First occurrence of %s in %s\n", search_string, find_haystack);
    printf("is at letter %d\n", index);
  }
}
*/

/******************************************************************/

char* readLine(FILE* file)
{
  /* read a line from file, alocate mem as we read */
  char* line = (char*) calloc(0, sizeof(char) );;
  char ch;
  int len = 0;

  while ( (ch = fgetc(file) ) != EOF && ch != '\n')
  {
    line = (char*) realloc(line, sizeof(char) * (len + 2) );
    line[len++] = ch;
    line[len] = '\0';
  }
  return line;
}
/******************************************************************/
int main(int argc, char* argv[]) {
    if  (! isatty(fileno(stdout))) {
      printf("is not tty\n");
      return 1;
    }
  
    char *mytty=ttyname(fileno(stdout));
    printf("Sending output to: %s\n",mytty);
    char *filename;
    if ( argc != 2 ) {
        fprintf(stderr, "Usage: %s <filename>\n",argv[0]);
        exit(EXIT_FAILURE);
    }
    //Get args
    filename=argv[1];
    replay(filename,mytty);
    printf("End replay\n");
    usleep (5000);
    exit(EXIT_SUCCESS);
    return (0);
}


/* man tty_ioctl
   Buffer count and flushing
       FIONREAD  int *argp
              Get the number of bytes in the input buffer.
  //returns 0 on success, -1 on error
  int ioctl(int fd, int cmd, ...);
  int *bytesInBuffer;
  int ioctl(int fd, FIONRED,bytesInBuffer );
*/
