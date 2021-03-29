#include <assert.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
  assert(argc == 4);

  int x = argv[1][0] - '0';
  int y = argv[2][0] - '0';
  int z = argv[3][0] - '0';

  int ans = 0;

  if (x >= 5) {
    ans = ans * 10 + 5;
  } else {
    ans += 1;
  }

  if (y >= 5) {
    ans = ans * 10 + 5;
  } else {
    ans += 1;
  }

  if (z >= 5) {
    ans = ans * 10 + 5;
  } else {
    ans += 1;
  }

  return 0;
}