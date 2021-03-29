#include <assert.h>

int main(int argc, char *argv[]) {

  int x;
  int i;
  int ans = 0;

  x = argv[1][0] - '0';

  for (i = 0; i < x; i++) {
    ans += i;
  }

  // when x == 10, ans = 45
  assert(ans != 45);

  return 0;
}
