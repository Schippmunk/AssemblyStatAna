#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

void fun1(char buf[]){
  char buf2[16];
  strcpy(buf2, buf);
}

int main() {
  int control;
  char buf[64];

  control = 13;
  fgets(buf, 20, stdin);

  fun1(buf);
}