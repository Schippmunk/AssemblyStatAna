#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main() {
  int control;
  char buf2[32];
  char buf1[64];

  control = 35;
  fgets(buf1, 32, stdin);
  buf1[65] = 'a';

  return 0;
}