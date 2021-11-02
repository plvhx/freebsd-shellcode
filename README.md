### FreeBSD (x86 / x86-64) shellcode

```
- FreeBSD / x86 execve("/bin/sh", {"/bin/sh", NULL}, NULL) 29 bytes shellcode
- FreeBSD / x86 '/bin/cat /etc/passwd' 48 bytes shellcode
- FreeBSD / x86 sys_chmod("/etc/passwd", 0777) 37 bytes shellcode
- FreeBSD / x86 setuid(0) + execve("/bin/sh", {"/bin/sh", NULL}, NULL) 37 bytes shellcode
```
