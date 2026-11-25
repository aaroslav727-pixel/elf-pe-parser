/* Sample program for binsec tests.
 * - a local char buffer, so -fstack-protector-strong emits a canary (__stack_chk_fail)
 * - memcpy/printf with a known destination size, so -D_FORTIFY_SOURCE=2 -O2
 *   turns them into __memcpy_chk / __printf_chk
 */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  char buf[64];
  const char *src = argc > 1 ? argv[1] : "hello, binsec";
  size_t n = strlen(src);
  if (n >= sizeof buf) n = sizeof buf - 1;
  memcpy(buf, src, n);
  buf[n] = '\0';
  printf("%s (%zu bytes)\n", buf, n);
  return 0;
}
