#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <printf.h>
#include <signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <ncurses.h>
/*look at from curs lib:
    man curs_getch 	
    man noecho
    man initscr
    man curs_util
  
  compile witk: 
     gcc cur_term.c -o cur_term -lncurses
*/


//prototype
int readChars(void);

int readChars(void) {
    int ch;
    int forever=1;
    while (forever) { 
      ch=getch(); 
      if ( ch=='q' ) break;
      int ich=toascii(ch);
      //addch(ch);
      echochar(ich);
      //printw(ch);
      //fputc(ch,stdout);  	
    }


}


//global vars
WINDOW *win; 
/******************************************************************/
int main(int argc, char* argv[]) {
    if  (! isatty(fileno(stdout))) {
      printf("is not tty\n");
      return 1;
    }
    //set the term into noecho mode
    nofilter();
    win=initscr();
    //cbreak(); //stop buffering on newline
    noecho(); //turn off echo
    raw();
    //nl();
    intrflush(win,FALSE);
    keypad(win,TRUE);
    readChars();
    sleep(1);
    //nocbreak();
    //clearok(win,TRUE);
    //clear();
    //win=initscr();
    //noraw();
    //nocbreak();
    //nl();
    //echo();
    endwin();	
}



