#ifndef RND_H
 #define RND_H

#include <stdint.h>
#include <stddef.h>

int verify_system_entropy(
  uint32_t,
  uint8_t *,
  size_t,
  uint64_t
);

void open_random(char *);

void close_random();

void clear_rnd(
  uint8_t *,
  size_t
);

#endif
