#include <unistd.h>
#include <stdlib.h>

enum PIPES {READ, WRITE};

int main(int argc, char**argv)
{
	if (argv[2])
	{
		int hpipe[2];
		pipe(hpipe);

		if (fork())
		{
			close(hpipe[WRITE]);
			dup2(hpipe[READ], 0);//stdin = 0
			close(hpipe[READ]);
			execlp(argv[2],argv[2],NULL);
		}
		else
		{
			close(hpipe[READ]);
			dup2(hpipe[WRITE], 1);//stdout = 1
			close(hpipe[WRITE]);
			execlp(argv[1],argv[1],NULL);
		}
	}
	exit(EXIT_SUCCESS);
}

