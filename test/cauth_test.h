#ifndef CAUTH_TEST_H
  #define CAUTH_TEST_H

bool time_const_compare(uint8_t *, ssize_t, uint8_t *, ssize_t);
void memcpy_max(uint8_t *, uint8_t *, ssize_t, ssize_t);
const uint8_t *get_buf_cmp1_dummy();
size_t get_buf_cmp1_dummy_size();
const uint8_t *get_buf_cmp2_dummy();
size_t get_buf_cmp2_dummy_size();
void memcpy_max(uint8_t *, uint8_t *, ssize_t, ssize_t);
void debug_dump(uint8_t *, size_t);
void debug_dump_ascii(uint8_t *, size_t);
int is_vec_content_eq(
  uint8_t *, size_t,
  uint8_t *, size_t
);

#define MAX_TIMEOUT_IN_SECOND 60

#endif

