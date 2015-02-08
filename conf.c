/* Test parsing config file */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>

#define LINE_LEN 100

//prototype
int read_conf( const char *config_file, const char *key, char **value);

int read_conf( const char *config_file, const char *key, char **value) {
    //reads config_file looking fir key, 
    // sets  value if found, null otherwise
    // returns -1 on FNF, 0 on keynot found, 1 on found
    FILE *fp;
    char line[LINE_LEN];
    int end;
    int retVal=0;
    int keyLen=strlen(key);

    if ( !(fp = fopen(config_file, "r")) ) {
        return(-1); /* Can't open file */
    }
    
    while (fgets(line, LINE_LEN, fp)) {
        /* All options are key=value (no spaces)*/
        //printf("line:%s",line);
        if (strncmp(line, key, keyLen) == 0) {
            if (*value!=NULL) free(*value);
            end = strlen(line);
            if (line[end-1] == '\n')
                line[end-1] = 0; /* Remove trailing newline */
            *value = strdup(line+keyLen+1); //add equal to  key=val
            //printf("Found key:%s val:%s\n",key,*value);
            if (fp!=NULL) fclose(fp);
            return(1); //happy return
        }
    }
    return 0; //unhappy return
}

int main(int argc, char* argv[]) {
    char* k="key1";
    char* v;
    int found;
    char* filename="slogger.conf";
    found=read_conf(filename,k,&v);
    if (found == 1) {
        printf("Key found key:%s val:%s\n",k,v);
    }
    else if (found == -1) {
        printf("File not found: %s\n",filename);
    }
    else {
        printf("Not found key:%s\n",k);
    }
}
