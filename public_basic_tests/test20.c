#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main() {
  int control;
  char buf2[32];
  char buf1[64];

  control = 5;
  fgets(buf1, 57, stdin);
  strcpy(buf2, buf1);

  return 0;
}