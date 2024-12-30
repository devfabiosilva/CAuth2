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

/**
 * @def F_ENTROPY_TYPE_PARANOIC
 * @brief Type of the very excelent entropy used for verifier. Very slow
 */
#define F_ENTROPY_TYPE_PARANOIC (uint32_t)1477682819

//#define F_ENTROPY_TYPE_EXCELENT (uint32_t)1475885281
/**
 * @def F_ENTROPY_TYPE_EXCELENT
 * @brief Type of the excelent entropy used for verifier. Slow
 */
#define F_ENTROPY_TYPE_EXCELENT (uint32_t)1476885281

//#define F_ENTROPY_TYPE_GOOD (uint32_t)1471531015
/**
 * @def F_ENTROPY_TYPE_GOOD
 * @brief Type of the good entropy used for verifier. Not so slow
 */
#define F_ENTROPY_TYPE_GOOD (uint32_t)1472531015

//#define F_ENTROPY_TYPE_NOT_ENOUGH (uint32_t)1470001808
/**
 * @def F_ENTROPY_TYPE_NOT_ENOUGH
 * @brief Type of the moderate entropy used for verifier. Fast
 */
#define F_ENTROPY_TYPE_NOT_ENOUGH (uint32_t)1471001808

//#define F_ENTROPY_TYPE_NOT_RECOMENDED (uint32_t)1469703345
/**
 * @def F_ENTROPY_TYPE_NOT_RECOMENDED
 * @brief Type of the not recommended entropy used for verifier. Very fast
 */
#define F_ENTROPY_TYPE_NOT_RECOMENDED (uint32_t)1470003345

#endif
