
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <unistd.h>
#include "main.h"


int
ptraceWrapper (
	enum __ptrace_request request,
	pid_t pid,
	void * addr,
	void * data
)
{
	int status = 0;

	errno = 0;
	status = ptrace(request, pid, addr, data);
	if (-1 == status)
	{
		fprintf(stderr, "Error during ptrace: %s\n", strerror(errno));
		return -1;
	}

	return status;
}

int
attach (
	const pid_t pid
)
{
	int status = -1;
	int result = -1;
	
	result = ptraceWrapper(PTRACE_ATTACH, pid, 0, 0);
	if (-1 == result)
	{
		fprintf(stderr, "Failed to attach to pid %d\n", pid);
		return -1;
	}

	result = waitpid(pid, &status, WUNTRACED);
	if (-1 == result)
	{
		fprintf(stderr, "Waitpid failed: %s\n", strerror(errno));
		return -1;
	}

	if ((pid != result) || (!WIFSTOPPED(status))
	{
		fprintf(stderr, "Unexpected status %d, result: %d\n", status, result);
		return -1;
	}

	printf("Successfully attached to pid %d\n", pid);

	return 0;
}


int
detach (
	const pid_t pid
)
{
	int status = -1;

	result = ptraceWrapper(PTRACE_DETACH, pid, 0, 0);
	if (-1 == result)
	{
		fprintf(stderr, "Failed to detach from pid %d\n", pid);
		return -1;
	}

	printf("Successfully detached from pid %d\n", pid);

	return 0;
}


pid_t
getPid (void)
{
	pid_t pid;
	int numRead = 0;
	
	printf("Enter the PID of the target executable: ");
	numRead = scanf("%d", pid);
	
	assert(1 == numRead);
	return pid;	
}


void
scanSyscalls (
	const pid_t pid
)
{
	bool done = false;

	while (!done)
	{
		
	}
}


int main (int argc, char * argv[])
{
	pid_t pid;
	printf("Starting Ptrace Wiper\n");
	
	// Grab a pid from the user
	pid = getPid();

	// Attach to the process
	attach(pid);

	// Allow the process to resume
	detach(pid);

	printf("Exiting...\n");
	return 0;
}

