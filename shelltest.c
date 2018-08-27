#include<stdio.h>
#include<string.h>
char *shellcode = "";

int main() {
  fprintf();
  (*(void(*)())  shellcode)();
  return 0;
}
