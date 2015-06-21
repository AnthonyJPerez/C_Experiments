
#include <assert.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include "main.h"


int
ptraceWrapper (
	enum __ptrace_request request,
	pid_t pid,
	int addr,
	int data
)
{
	int status = 0;

	errno = 0;
	status = ptrace(request, pid, (void *)addr, (void *)data);
	if (-1 == status)
	{
		fprintf(stderr, "Error during ptrace: %s\n", strerror(errno));
		return -1;
	}

	return status;
}


int
writeDataToProcess (
	const pid_t pid,
	const uintptr_t addr,
	const uint8_t * data,
	const size_t length
)
{
	int bytesLeft = length;
	uint32_t * dwordPtr = (uint32_t *)data;

	while (bytesLeft > 0)
	{
		if (-1 == ptraceWrapper(PTRACE_POKEDATA, pid, addr, (int)(*dwordPtr)))
		{
			fprintf(stderr, "Failed to POKEDATA (pid: %d, addr: %p, data: %p:%d, length: %zu, bytesLeft: %d\n",
				pid, (void*)addr, dwordPtr, (dwordPtr)?*dwordPtr:0, length, bytesLeft);
		}
		++dwordPtr;
		bytesLeft -= sizeof(uint32_t);
	}
}


int
readDataFromProcess (
	const pid_t pid,
	const uintptr_t addr,
	const size_t length,
	uint8_t * const outputBuffer
)
{
	size_t offset = 0;
	uint32_t * dwordPtr = (uint32_t *)outputBuffer;

	while (offset < length)
	{
		if (-1 == ptraceWrapper(PTRACE_PEEKDATA, pid, (int)(addr+offset), NULL))
		{
			//fprintf(stderr, "Failed to POKEDATA (pid: %d, addr: %p, data: %p:%d, length: %zu, bytesLeft: %d\n",
				//pid, (void*)addr, dwordPtr, (dwordPtr)?*dwordPtr:0, length, bytesLeft);
		}
		offset += sizeof(uint32_t);
	}
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
		fprintf(stderr, "Failed to attach to pid %d - %s\n", pid, strerror(errno));
		return -1;
	}

	result = waitpid(pid, &status, WUNTRACED);
	if (-1 == result)
	{
		fprintf(stderr, "Waitpid failed: %s\n", strerror(errno));
		return -1;
	}

	if ((pid != result) || (!WIFSTOPPED(status)))
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
	int result = -1;

	result = ptraceWrapper(PTRACE_DETACH, pid, 0, 0);
	if (-1 == result)
	{
		fprintf(stderr, "Failed to detach from pid %d - %s\n", pid, strerror(errno));
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
	numRead = scanf("%d", (int *)&pid);
	
	assert(1 == numRead);
	return pid;	
}


void preAnalyzeSyscall(
	const pid_t pid
)
{
	long sys_call_nr = 0;
	long addr = 0;
	long length = 0;
	struct user_regs_struct regs;

	memset(&regs, 0, sizeof(regs));
	ptraceWrapper(PTRACE_GETREGS, pid, 0, (int)&regs);

#ifdef __i386__
		sys_call_nr = regs.orig_eax;
		addr = regs.ebx;
		length = regs.ecx;
#elif __x86_64__
		sys_call_nr = regs.orig_rax;
		addr = regs.rbx;
		length = regs.rcx;
#else
#error "Unsupported architecture."
#endif

	if (SYS_munmap == sys_call_nr)
	{
		uint8_t zeroBuffer[length];
		memset(zeroBuffer, 0, sizeof(zeroBuffer));

		printf("About to enter munmap(%p, %ld)\n", (void*)addr, length);
		printf("Writing zero's to the map\n");
		readDataFromProcess(pid, addr, length);
		writeDataToProcess(pid, addr, zeroBuffer, length);
		readDataFromProcess(pid, addr, length);
	}
}


void postAnalyzeSyscall (
	const pid_t pid
)
{
	int sys_call_nr = 0;
	struct user_regs_struct regs;

	memset(&regs, 0, sizeof(regs));
	ptraceWrapper(PTRACE_GETREGS, pid, 0, (int)&regs);

#ifdef __i386__
		sys_call_nr = regs.orig_eax;
#elif __x86_64__
		sys_call_nr = regs.orig_rax;
#else
#error "Unsupported architecture."
#endif

	if (SYS_munmap == sys_call_nr)
	{
		printf("Returned from munmap()\n");
	}
}


int
scanSyscalls (
	const pid_t pid
)
{
	bool done = false;
	int result = 0;
	int lastSignal = 0;
	bool isSyscallEntry = true;

	printf("scanSyscalls()\n");

	ptraceWrapper(PTRACE_SETOPTIONS, pid, 0, 
		PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXIT);

	printf("ptrace options set\n");

	while (!done)
	{
		lastSignal = 0;
		//printf("About to PTRACE_SYSCALL\n");
		
		// Continue the process until the next syscall
		result = ptraceWrapper(PTRACE_SYSCALL, pid, 0, lastSignal);
		if (-1 == result)
		{
			fprintf(stderr, "Failed during PTRACE_SYSCALL - %s\n", strerror(errno));
			return -1;
		}

		result = waitpid(pid, &lastSignal, WUNTRACED | WCONTINUED);
		if (-1 == result)
		{
			fprintf(stderr, "Waitpid failed: %s\n", strerror(errno));
			return -1;
		}

		//if (status == (SIGTRAP | PTRACE_EVENT_EXIT << 8))
		//{
		//	fprintf(stderr, "SIGTRAP reached\n");
	    //    break;
	    //}

	    if (isSyscallEntry)
	    {
	    	preAnalyzeSyscall(pid);
	    }
	    else
	    {
	    	postAnalyzeSyscall(pid);
	    }

	    isSyscallEntry = !isSyscallEntry;
	}

	return 0;
}


int main (int argc, char * argv[])
{
	pid_t pid;
	printf("Starting Ptrace Wiper\n");
	
	// Grab a pid from the user
	pid = getPid();

	// Attach to the process
	attach(pid);

	// Look for munmap
	scanSyscalls(pid);

	// Allow the process to resume
	detach(pid);

	printf("Exiting...\n");
	return 0;
}
