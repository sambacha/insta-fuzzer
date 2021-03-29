#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {

  sprintf((char *)(long)argc, "%d", 1);

  return 0;
}