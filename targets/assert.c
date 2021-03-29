#include <assert.h>

int main(int argc, char *argv[]) {

  char *x = argv[1];
  assert(x[0] != 'a');
  assert(x[0] != 'b');

  return 0;
}