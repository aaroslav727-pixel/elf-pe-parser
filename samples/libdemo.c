/* Shared-library sample (checksec reports PIE as "DSO"). */
#include <string.h>

int demo_copy(char *dst, const char *src, unsigned long size) {
  char tmp[32];
  strncpy(tmp, src, sizeof tmp - 1);
  tmp[sizeof tmp - 1] = '\0';
  if (size == 0) return -1;
  strncpy(dst, tmp, size - 1);
  dst[size - 1] = '\0';
  return (int)strlen(dst);
}
