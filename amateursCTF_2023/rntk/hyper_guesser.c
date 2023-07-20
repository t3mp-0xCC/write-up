#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
  time_t seed;
  seed = time(NULL);
  srand(seed);
  printf("guess: %d\n", rand());
  getchar();
}
