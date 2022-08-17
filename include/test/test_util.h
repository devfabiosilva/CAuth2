#ifndef TEST_UTIL_H
 #define TEST_UTIL_H

#include <stdio.h>
#include <stdint.h>

int gen_rand_no_entropy_util(uint8_t *, size_t, int *, void *);
int test_vector(uint8_t *, size_t, uint8_t);

const char *CONST_STR_TEST[]={
    "Hey !!", "Test 123", "TEST", "TEST 123", "This is a text", "Testing test string", "0123456789", "Bitcoin", "BITCOIN",
    "Buy Bitcoin", "BUY BITCOIN", "C is a very cool language", "Linux", "Simple text ~ ç` àá&1928", "VLSI world", "transistor",
    "", "Empty", "Main text", "Source code", "Hello World", "HELLO WORLD", "Santos Dummond", "Tesla, Nikola",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567890", "Blá blá, blá", "Linux inside here", "IoT", "Embedded systems",
    "CTest is amazing !!!", "C is powerful"
};

#define CONST_STR_TEST_ELEMENTS (sizeof(CONST_STR_TEST)/sizeof(CONST_STR_TEST[0]))

#endif