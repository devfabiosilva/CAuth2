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
 * @version 0.1.0
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

#define TRUE (int)(1==1)
#define FALSE (int)(1!=1)

#define ALG_SHA1_DEFAULT (int)2
#define ALG_SHA256 (int)4
#define ALG_SHA512 (int)6

typedef int CAUTH_BOOL;

typedef enum cauth_2fa_auth_code_err_t {
   CAUTH_2FA_ERR_EMPTY_KEY_SIZE=10800,
   CAUTH_2FA_ERR_INVALID_ALG_TYPE,
   CAUTH_2FA_ERR_HMAC_MALLOC_ERROR,
   CAUTH_2FA_ERR_DIGIT_SIZE,
   CAUTH_2FA_ERR_TOTP_NULL_STR,
   CAUTH_2FA_ERR_DIV_ZERO,
   CAUTH2_2FA_BASE32_ALLOC,
   CAUTH2_2FA_BASE32_DECODE,
   CAUTH2_2FA_BASE32_ZERO_SZ,
   CAUTH_2FA_ERR_WRONG_KEY_SIZE
} CAUTH_2FA_AUTH_CODE_ERR;

typedef enum cauth_sign_err_t {
   CAUTH_EMPTY_KEY_ERR=10700,
   CAUTH_EMPTY_MESSAGE,
   CAUTH_ERR_INVALID_ALG_TYPE,
   CAUTH_SIGN_ALLOC
} CAUTH_SIGN_CODE_ERR;

typedef enum cauth_verify_err_t {
   CAUTH_VERIFY_SIGNATURE_ERR=-40,
   CAUTH_VERIFY_WRONG_SIZE_ERR,
   CAUTH_VERIFY_INVALID=3033,
   CAUTH_VERIFY_OK=1981
} CAUTH_VERIFY_CODE_ERR;

#define ERROR_SUCCESS (int)0

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

CAUTH_VERIFY_CODE_ERR
cauth_verify_message_with_err(
   uint8_t *, size_t,
   int,
   uint8_t *, size_t,
   uint8_t *, size_t
);

CAUTH_BOOL
cauth_verify_message(
   uint8_t *, size_t,
   int,
   uint8_t *, size_t,
   uint8_t *, size_t
);

typedef enum hex2str_type_t {
   IS_LOWER_CASE=0,
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
#endif