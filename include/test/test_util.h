#ifndef TEST_UTIL_H
 #define TEST_UTIL_H

#include <stdio.h>
#include <stdint.h>

int gen_rand_no_entropy_util(uint8_t *, size_t, int *, void *);
int test_vector(uint8_t *, size_t, uint8_t);

#endif