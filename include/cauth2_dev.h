/**
 * @file
 * @brief CAuth2 is a tiny C TOTP Auth2 authenticator
 * @mainpage Overview
 *
 * ## Usage
 *
 * To compile C library (static and dynamic):
 *
 * ```sh
 * make
 * ```
 *
 * To build with test:
 *
 * ```sh
 * make test
 * ```
 *
 * ### Note
 *
 * By default it is compiled in _little_endian_. If you want to compile in _big_endian_ type:
 *
 * ```sh
 * make ENDIANESS=CAUTH_BIG_ENDIAN
 * ```
 *
 * To build documentation:
 *
 * ```sh
 * make doc
 * ```
 *
 * To clean documentation:
 *
 * ```sh
 * make doc_clean
 * ```
 *
 * To clean build:
 *
 * ```sh
 * make clean
 * ```
 * 
 * ## panelauth library for Python3
 *
 * This tiny library has a _panelauth_ library for Python 3.
 *
 * To compile just type:
 *
 * ```sh
 * make panelauth_build
 * ```
 *
 * To install:
 *
 * ```sh
 * make panelauth_install
 * ```
 *
 * ### DEBUG MODE
 *
 * If you want to debug type
 * 
 * _To compile just type:_
 *
 * ```sh
 * make panelauth_build DEBUG=P_DEBUG
 * ```
 *
 * _To install:_
 *
 * ```sh
 * make panelauth_install DEBUG=P_DEBUG
 * ```
 * 
 * ## Changelogs
 * 
 * See <a href="https://github.com/devfabiosilva/CAuth2/blob/master/CHANGELOG.md">here</a>
 *  
 * ## Credits
 *
 * @author Fábio Pereira da Silva
 * @date Jun 19 2022
 * @version 0.2.1
 * @copyright License MIT <a href="https://github.com/devfabiosilva/CAuth2/blob/master/LICENSE">see here</a>
 *
 * ## Contact
 *
 * mailto:fabioegel@gmail.com
 * 
 * ## Donations are wellcome :)
 *
 * **Bitcoin**: `1EcvCevxkbDvYXLuo8UzyG8YxJk78Lwe3e`
 */

#ifndef CAUTH2_H
 #define CAUTH2_H

#include <time.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

/**
 * @def TRUE
 * @brief CAuth2 _TRUE_
 */
#define TRUE (int)(1==1)

/**
 * @def FALSE
 * @brief CAuth2 _FALSE_
 */
#define FALSE (int)(1!=1)

/**
 * @def ALG_SHA1
 * @brief SHA1 Algorithm
 */
#define ALG_SHA1 (int)5

/**
 * @def ALG_SHA256
 * @brief SHA256 Algorithm
 */
#define ALG_SHA256 (int)9

/**
 * @def ALG_SHA512
 * @brief SHA512 Algorithm
 */
#define ALG_SHA512 (int)0x0b

/**
 * @typedef CAUTH_BOOL
 * @brief CAuth2 boolean type
 */
typedef int CAUTH_BOOL;

/**
 * @typedef CAUTH_2FA_AUTH_CODE_ERR
 * @brief CAuth2 2FA error code
 *
 * @enum cauth_2fa_auth_code_err_t
 */
typedef enum cauth_2fa_auth_code_err_t {
   /** Empty key size */
   CAUTH_2FA_ERR_EMPTY_KEY_SIZE=10800,
   /** Invalid algorithm type */
   CAUTH_2FA_ERR_INVALID_ALG_TYPE,
   /** Allocate HMAC error */
   CAUTH_2FA_ERR_HMAC_MALLOC_ERROR,
   /** Digit size error */
   CAUTH_2FA_ERR_DIGIT_SIZE,
   /** NULL string */
   CAUTH_2FA_ERR_TOTP_NULL_STR,
   /** Error zero divide */
   CAUTH_2FA_ERR_DIV_ZERO,
   /** Alloc Base32 */
   CAUTH2_2FA_BASE32_ALLOC,
   /** Error Base32 decode */
   CAUTH2_2FA_BASE32_DECODE,
   /** Zero size Base32 */
   CAUTH2_2FA_BASE32_ZERO_SZ,
   /** 2FA wrong key size */
   CAUTH_2FA_ERR_WRONG_KEY_SIZE
} CAUTH_2FA_AUTH_CODE_ERR;

/**
 * @typedef CAUTH_SIGN_CODE_ERR
 * @brief CAuth2 signing error code
 *
 * @enum cauth_sign_err_t
 */
typedef enum cauth_sign_err_t {
   /** Empty key error */
   CAUTH_EMPTY_KEY_ERR=10700,
   /** Empty message */
   CAUTH_EMPTY_MESSAGE,
   /** Invalid algorithm type */
   CAUTH_ERR_INVALID_ALG_TYPE,
   /** Allocation sign error */
   CAUTH_SIGN_ALLOC
} CAUTH_SIGN_CODE_ERR;

/**
 * @typedef CAUTH_VERIFY_CODE_ERR
 * @brief CAuth2 verity error code
 *
 * @enum cauth_verify_err_t
 */
typedef enum cauth_verify_err_t {
   /** Signature error */
   CAUTH_VERIFY_SIGNATURE_ERR=-40,
   /** Wrong size error */
   CAUTH_VERIFY_WRONG_SIZE_ERR,
   /** Verify invalid signature */
   CAUTH_VERIFY_INVALID=3033,
   /** Verify OK */
   CAUTH_VERIFY_OK=1981
} CAUTH_VERIFY_CODE_ERR;

/**
 * @def ERROR_SUCCESS
 * @brief CAuth2 error success
 */
#define ERROR_SUCCESS (int)0

/**
 * @fn CAUTH_2FA_AUTH_CODE_ERR cauth_2fa_auth_code(
 *    uint32_t *output,
 *    int alg_type,
 *    uint8_t *key,
 *    size_t key_sz,
 *    int is_key_base32,
 *    uint64_t T0,
 *    uint64_t X,
 *    time_t *T,
 *    uint8_t digit_size
 * )
 *
 * @brief Get OAuth2 code from given _key_
 * 
 * @param [out] output Output OAuth2 code
 * @param [in] alg_type Algorithm _type_  are:
 * 
 * ```sh
 * ALG_SHA1_DEFAULT
 * ALG_SHA256
 * ALG_SHA512
 * ```
 * @param [in] key Pointer of _input_ secret key
 * @param [in] key_sz Size of _input_ secret key
 * @param [in] is_key_base32 Any value != 0 means is Key is Base32 encoded
 * @param [in] T0 Initial Unix time. Usually _T0 = 0_
 * @param [in] X Is the time step. Usually _X = 30_ in seconds
 * @param [in] T Pointer of Unix time value. If _NULL_ this function computes current system Unix time
 * @param [in] digit_size Size of output digit. Usually _digit_size = 6_
 * 
 * @retval 0 if success or non zero if error
 * 
 */
CAUTH_2FA_AUTH_CODE_ERR
cauth_2fa_auth_code(
   uint32_t *,
   int,
   uint8_t *,
   size_t,
   int,
   uint64_t,
   uint64_t,
   time_t *,
   uint8_t
);

/**
 * @fn CAUTH_SIGN_CODE_ERR sign_message_dynamic(
 *    void **signature, size_t *signature_size,
 *    int alg_type,
 *    uint8_t *key, size_t key_size,
 *    uint8_t *message, size_t message_size
 * )
 *
 * @brief Signs dynamically one _message_ using _key_ with given algorithm
 * 
 * @param [out] signature Pointer with new allocated memory with signature
 * @param [out] signature_size Size of output signature
 * @param [in] alg_type Algorithm _type_  are:
 * 
 * ```sh
 * ALG_SHA1_DEFAULT
 * ALG_SHA256
 * ALG_SHA512
 * ```
 * @param [in] key Pointer of _input_ secret key
 * @param [in] key_size Size of _input_ secret key
 * @param [in] message Pointer of _input_ message
 * @param [in] message_size Size of pointer _input_ message size
 * 
 * _WARNING_ `signature` must be free after use
 *
 * @retval 0 if success or non zero if error
 * 
 */
CAUTH_SIGN_CODE_ERR
sign_message_dynamic(
   void **, size_t *,
   int,
   uint8_t *, size_t,
   uint8_t *, size_t
);

/**
 * @fn int cauth_str_to_hex(
 *  uint8_t *hex_stream,
 *  char *str,
 *  size_t len
 * )
 * @brief Parses hex string into binary
 * 
 * @param [out] hex_stream Pointer of output data
 * @param [in] str Input pointer hex string to be parsed
 * @param [in] len Length of _str_ pointer. If 0 it will calculate the length of _str_
 * 
 * _WARNING_: _hex_stream_ needs at least _len(str) / 2_ in size
 * 
 * @retval 0 if success or non zero if error
 * 
 */
int
cauth_str_to_hex(
   uint8_t *,
   char *,
   size_t
);


/**
 * @fn CAUTH_VERIFY_CODE_ERR cauth_verify_message_with_err(
 *    uint8_t *signature, size_t signature_size,
 *    int alg_type,
 *    uint8_t *key, size_t key_size,
 *    uint8_t *message, size_t message_size
 * )
 *
 * @brief Checks if _message_ has valid signature returning valid or error
 * 
 * @param [out] signature Pointer of signature
 * @param [out] signature_size Size of output signature
 * @param [in] alg_type Algorithm _type_
 * 
 * ```sh
 * ALG_SHA1_DEFAULT
 * ALG_SHA256
 * ALG_SHA512
 * ```
 * @param [in] key Pointer of private key
 * @param [in] key_size Size of private key
 * @param [in] message Pointer of message to be verified
 * @param [in] message_size Size of message to be verified
 * 
 * @retval CAUTH_VERIFY_OK if _signature_ is **valid** or else CAUTH_VERIFY_CODE_ERR
 * 
 */
CAUTH_VERIFY_CODE_ERR
cauth_verify_message_with_err(
   uint8_t *, size_t,
   int,
   uint8_t *, size_t,
   uint8_t *, size_t
);

/**
 * @fn CAUTH_BOOL cauth_verify_message(
 *    uint8_t *signature, size_t signature_size,
 *    int alg_type,
 *    uint8_t *key, size_t key_size,
 *    uint8_t *message, size_t message_size
 * )
 *
 * @brief Checks if _message_ has valid signature
 * 
 * @param [out] signature Pointer of signature
 * @param [out] signature_size Size of output signature
 * @param [in] alg_type Algorithm _type_
 * 
 * ```sh
 * ALG_SHA1_DEFAULT
 * ALG_SHA256
 * ALG_SHA512
 * ```
 * @param [in] key Pointer of private key
 * @param [in] key_size Size of private key
 * @param [in] message Pointer of message to be verified
 * @param [in] message_size Size of message to be verified
 * 
 * @retval TRUE if _signature_ is **valid** or else _FALSE_
 * 
 */
CAUTH_BOOL
cauth_verify_message(
   uint8_t *, size_t,
   int,
   uint8_t *, size_t,
   uint8_t *, size_t
);

/**
 * @typedef HEX2STR_TYPE
 * @brief CAuth2 Hex string case
 *
 * @enum hex2str_type_t
 */
typedef enum hex2str_type_t {
   /** Set hex string is lower case*/
   IS_LOWER_CASE=0,
   /** Set hex string is upper case*/
   IS_UPPER_CASE=1
} HEX2STR_TYPE;

/**
 * @fn char *cauth_hex2str_dynamic(
 *  const uint8_t *buf,
 *  size_t buf_sz,
 *  HEX2STR_TYPE type
 * )
 * @brief Parses binary to hex string
 * 
 * @param [in] buf Pointer of binary data
 * @param [in] buf_sz Size of _buf_
 * @param [in] type Type of _IS_LOWER_CASE_ or _IS_UPPER_CASE_
 * 
 * It must be free after use
 * 
 * @retval New string pointer or _NULL_ if error
 * 
 */
char *
cauth_hex2str_dynamic(
   const uint8_t *,
   size_t,
   HEX2STR_TYPE
);

/**
 * @fn CAUTH_2FA_AUTH_CODE_ERR check_base32_oauth_key_valid(
 *    size_t *output_size,
 *    const char *input, size_t input_sz,
 *    int alg_type
 * )
 * @brief Check is Base32 secret key is valid
 * 
 * @param [out] output_size Pointer of _output_ size of secret key. It can be _NULL_
 * @param [in] input Pointer of _input_ secret key in Base32
 * @param [in] input_sz Size of _input_ secret key
 * @param [in] alg_type Algorithm type. See ALG_SHA1_DEFAULT ALG_SHA256 ALG_SHA512
 * 
 * @retval ERROR_SUCCESS or CAUTH_2FA_AUTH_CODE_ERR on error
 */
CAUTH_2FA_AUTH_CODE_ERR
check_base32_oauth_key_valid(
   size_t *,
   const char *, size_t,
   int
);

/**
 * @fn const char *cauth_getVersion()
 * @brief Get CAuth2 current version
 */
const char *
cauth_getVersion();

/**
 * @fn const char *cauth_buildDate()
 * @brief Get CAuth2 build date
 */
const char *
cauth_buildDate();

/**
 * @fn const char *cauth_endianess()
 * @brief Get CAuth2 compilation architecture endianess
 */
const char *
cauth_endianess();

/**
 * @def ENTROPY_TYPE_PARANOIC
 * @brief Type of the very excelent entropy used for verifier. Very slow
 */
#define ENTROPY_TYPE_PARANOIC (uint32_t)1477682819

//#define ENTROPY_TYPE_EXCELENT (uint32_t)1475885281
/**
 * @def F_ENTROPY_TYPE_EXCELENT
 * @brief Type of the excelent entropy used for verifier. Slow
 */
#define ENTROPY_TYPE_EXCELENT (uint32_t)1476885281

//#define ENTROPY_TYPE_GOOD (uint32_t)1471531015
/**
 * @def ENTROPY_TYPE_GOOD
 * @brief Type of the good entropy used for verifier. Not so slow
 */
#define ENTROPY_TYPE_GOOD (uint32_t)1472531015

//#define ENTROPY_TYPE_NOT_ENOUGH (uint32_t)1470001808
/**
 * @def ENTROPY_TYPE_NOT_ENOUGH
 * @brief Type of the moderate entropy used for verifier. Fast
 */
#define ENTROPY_TYPE_NOT_ENOUGH (uint32_t)1471001808

//#define ENTROPY_TYPE_NOT_RECOMENDED (uint32_t)1469703345
/**
 * @def ENTROPY_TYPE_NOT_RECOMENDED
 * @brief Type of the not recommended entropy used for verifier. Very fast
 */
#define ENTROPY_TYPE_NOT_RECOMENDED (uint32_t)1470003345

int
generate_key_dynamic(
  uint8_t **,
  size_t *,
  int,
  uint32_t,
  uint64_t,
  const char *
);

int
generate_totp_key_dynamic(
  const char **,
  size_t *,
  int,
  uint32_t,
  uint64_t,
  const char *
);

/**
 * @def DEFAULT_TIMEOUT_IN_SECOND
 * @brief Default timeout for generating random keys
 */
#define DEFAULT_TIMEOUT_IN_SECOND 120

/**
 * @fn bool check_entropy_value(
 *  long int value
 * )
 * @brief Check if selected entropy type is valid
 * 
 * @param [in] value Entropy value
 * 
 * @retval _true_ if is valid
 * 
 */
bool check_entropy_value(
  long int
);

void clear_rnd_and_free(
  uint8_t **,
  size_t,
  const char *
);

int decode_totp_key_with_alg_check_dynamic(
  uint8_t **out, size_t *out_sz,
  int alg,
  const char *in, ssize_t in_len
);

int encode_totp_key_with_alg_check_dynamic(
  const char **out, size_t *out_sz,
  int alg,
  const uint8_t *in, size_t in_len
);

#endif

