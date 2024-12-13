#ifndef CAUTH_TEST_H
  #define CAUTH_TEST_H

bool time_const_compare(uint8_t *, uint8_t *, size_t);
const uint8_t *get_buf_cmp1_dummy();
size_t get_buf_cmp1_dummy_size();
const uint8_t *get_buf_cmp2_dummy();
size_t get_buf_cmp2_dummy_size();
void memcpy_max(uint8_t *, uint8_t *, ssize_t, ssize_t);

#endif

