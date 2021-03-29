#include <assert.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
  char x = argv[1][0];

  int y;
  if (x < 'e') {
    y = 1;
  } else if (x < 'j') {
    y = 2;
  } else {
    y = 3;
  }

  if (x < 'g') {
    y *= 3;
  } else {
    y *= 4;
  }

  // printf("%d\n", y);

  // printf("%d\n", y);

  return 0;
}
