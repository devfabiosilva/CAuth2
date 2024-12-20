#include <cauth2_dev.h>
#include <cyoencode/CyoDecode.h>
#include <cyoencode/CyoEncode.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>
#include <stdio.h>
#include <version.h>

_Static_assert(sizeof(int)==sizeof(mbedtls_md_type_t), "wrong mbedtls_md_type_t size");
_Static_assert(ALG_SHA1_DEFAULT==MBEDTLS_MD_SHA1, "wrong ALG_SHA1_DEFAULT value");
_Static_assert(ALG_SHA256==MBEDTLS_MD_SHA256, "wrong ALG_SHA256 value");
_Static_assert(ALG_SHA512==MBEDTLS_MD_SHA512, "wrong ALG_SHA512 value");

static fn_rand _fn_rand=NULL;

const char *
cauth_getVersion()
{
   return VERSION"."VERSION_MAJOR"."VERSION_MINOR;
}

const char *
cauth_buildDate()
{
   return BUILD_YEAR BUILD_MONTH BUILD_DAY BUILD_HOUR;
}

const char *
cauth_endianess()
{
   return
#ifdef CAUTH_LITTLE_ENDIAN
   "LE";
#else
   "BE";
#endif
}

static
int cauth_sha256_digest_dynamic_util(
   void **res,
   uint8_t *msg,
   size_t msg_size
)
{
   int err;
   mbedtls_sha256_context *sha256;

   if (!(*res=malloc(32)))
      return 5861;

   if (!(sha256=malloc(sizeof(mbedtls_sha256_context)))) {
      err=5862;
      goto cauth_sha256_digest_EXIT1;
   }

   mbedtls_sha256_init(sha256);

   if ((err=mbedtls_sha256_starts(sha256, 0)))
      goto cauth_sha256_digest_EXIT;

   if ((err=mbedtls_sha256_update(sha256, msg, msg_size)))
      goto cauth_sha256_digest_EXIT;

   err=mbedtls_sha256_finish(sha256, (unsigned char *)*res);

cauth_sha256_digest_EXIT:
   mbedtls_sha256_free(sha256);
   memset(sha256, 0, sizeof(mbedtls_sha256_context));
   free(sha256);

   if (err) {
cauth_sha256_digest_EXIT1:
      free(*res);
      *res=NULL;
   }

   return err;
}

#define CLEAR_SHA256_DGST(m) \
   memset(m, 0, 32);\
   free(m);

static
CAUTH_2FA_AUTH_CODE_ERR
cauth_base32_decode_dynamic_util(
    void **p_key, size_t *p_key_size,
    const char *input, size_t input_sz
)
{
   *p_key=NULL;
   
   if (!(*p_key_size=cyoBase32DecodeGetLength(input_sz)))
      return CAUTH2_2FA_BASE32_ZERO_SZ;

    if (!(*p_key=malloc(*p_key_size)))
        return CAUTH2_2FA_BASE32_ALLOC;

    if ((*p_key_size=cyoBase32Decode((void *)*p_key, (const char *)input, input_sz)))
        return ERROR_SUCCESS;

    free(*p_key);
    *p_key=NULL;
    return CAUTH2_2FA_BASE32_DECODE;
}

CAUTH_2FA_AUTH_CODE_ERR
check_base32_oauth_key_valid(
   size_t *output_size,
   const char *input, size_t input_sz,
   int alg_type
)
{
   int err;
   void *p_key;
   size_t output_size_tmp;
   const mbedtls_md_info_t *info_sha;

   if (output_size)
      *output_size=0;

   if (!(info_sha=mbedtls_md_info_from_type((mbedtls_md_type_t)alg_type)))
      return CAUTH_2FA_ERR_INVALID_ALG_TYPE;

   if ((err=cauth_base32_decode_dynamic_util(&p_key, &output_size_tmp, input, input_sz)))
      return err;

   memset(p_key, 0, output_size_tmp);
   free(p_key);

   if ((err=(output_size_tmp!=(size_t)mbedtls_md_get_size(info_sha))))
      output_size_tmp=0;

   if (output_size)
      *output_size=output_size_tmp;

   return err;
}

char *
cauth_hex2str_dynamic(
   const uint8_t *buf,
   size_t buf_sz,
   HEX2STR_TYPE type
)
{

   char *res;
   char *p;
   static const char *f[]={"%02x","%02X"};
   const char *q;

   if (!buf_sz)
      return NULL;

   if (!(res=malloc((2*buf_sz)+1)))
      return NULL;

   p=res;
   q=f[type];

   for (;buf_sz--;) {
      sprintf(p, q, (unsigned char)*((unsigned char *)buf++));
      p+=2;
   }

   return res;
}

CAUTH_2FA_AUTH_CODE_ERR
cauth_2fa_auth_code(
   uint32_t *output,
   int alg_type,
   uint8_t *key,
   size_t key_sz,
   int is_key_base32,
   uint64_t T0,
   uint64_t X,
   time_t *T,
   uint8_t digit_size
)
{
   int
#ifdef CAUTH_LITTLE_ENDIAN
      i,
#elif CAUTH_BIG_ENDIAN
#else
 #error "Could not compile. Choose CAUTH_LITTLE_ENDIAN or CAUTH_BIG_ENDIAN"
#endif
      err;

   const uint32_t
      digits_power[]={1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};

   size_t
      offset,
      p_key_sz;

   union c_val_u {
      uint8_t u8[sizeof(uint64_t)];
      uint64_t u64;
   } C_VAL;

   uint8_t *p_key;
   unsigned char *hmac_output;
   const mbedtls_md_info_t *info_sha;
   #define DIGITS_POWER_INDEX sizeof(digits_power)/sizeof(digits_power[0])

   if (!X)
      return CAUTH_2FA_ERR_DIV_ZERO;

   if (!key_sz)
      return CAUTH_2FA_ERR_EMPTY_KEY_SIZE;

   if ((size_t)digit_size>=DIGITS_POWER_INDEX)
      return CAUTH_2FA_ERR_DIGIT_SIZE;

   if (!(info_sha=mbedtls_md_info_from_type((mbedtls_md_type_t)alg_type)))
      return CAUTH_2FA_ERR_INVALID_ALG_TYPE;

   if (is_key_base32) {
      if ((err=cauth_base32_decode_dynamic_util((void **)&p_key, &p_key_sz, (const char *)key, key_sz)))
         return err;
   } else {
      p_key=key;
      p_key_sz=key_sz;
   }

//   BEGIN
//   Keys SHOULD be of the length of the HMAC output to facilitate
//   interoperability. See 5.1 @ https://datatracker.ietf.org/doc/html/rfc6238
   if (p_key_sz!=(size_t)mbedtls_md_get_size(info_sha)) {
      err=CAUTH_2FA_ERR_WRONG_KEY_SIZE;
      goto cauth_2fa_auth_code_EXIT1;
   }
//   END

   if (!(hmac_output=malloc(p_key_sz))) {
      err=CAUTH_2FA_ERR_HMAC_MALLOC_ERROR;
      goto cauth_2fa_auth_code_EXIT1;
   }

   C_VAL.u64=(T)?((((uint64_t)*T)-T0)/X):((((uint64_t)time(NULL))-T0)/X);

#ifdef CAUTH_LITTLE_ENDIAN
   memcpy(hmac_output, C_VAL.u8, sizeof(uint64_t));
   hmac_output+=sizeof(uint64_t);
   for (i=0;i<sizeof(uint64_t);)
      C_VAL.u8[i++]=*(--hmac_output);
#endif

   if ((err=mbedtls_md_hmac(
      info_sha,
      (const unsigned char *)p_key, p_key_sz,
      (const unsigned char *)&C_VAL.u64, sizeof(uint64_t),
      (unsigned char *)hmac_output
   ))) goto cauth_2fa_auth_code_EXIT2;

   offset=(size_t)(hmac_output[p_key_sz-1]&0x0F);

   *output=(uint32_t)((hmac_output[offset++]&0x7F)<<24);
   *output|=(uint32_t)((hmac_output[offset++])<<16);
   *output|=(uint32_t)((hmac_output[offset++])<<8);
   *output|=(uint32_t)(hmac_output[offset]);

   *output=(*output)%(digits_power[(size_t)digit_size]);

cauth_2fa_auth_code_EXIT2:
   memset(hmac_output, 0, p_key_sz);
   free(hmac_output);

cauth_2fa_auth_code_EXIT1:
   if (key!=p_key) {
      memset(p_key, 0, p_key_sz);
      free(p_key);
   }

   return err;
   #undef DIGITS_POWER_INDEX
}

CAUTH_SIGN_CODE_ERR
sign_message_dynamic(
   void **signature, size_t *signature_size,
   int alg_type,
   uint8_t *key, size_t key_size,
   uint8_t *message, size_t message_size
)
{
   int err;
   const mbedtls_md_info_t *info_sha;
   uint8_t *sha256;

   *signature=NULL;
   *signature_size=0;

   if (!key_size)
      return CAUTH_EMPTY_KEY_ERR;

   if (!message_size)
      return CAUTH_EMPTY_MESSAGE;

   if (!(info_sha=mbedtls_md_info_from_type((mbedtls_md_type_t)alg_type)))
      return CAUTH_ERR_INVALID_ALG_TYPE;

   if (!((*signature)=malloc(*signature_size=(size_t)mbedtls_md_get_size(info_sha))))
      return CAUTH_SIGN_ALLOC;

   if ((err=cauth_sha256_digest_dynamic_util((void *)&sha256, key, key_size)))
      goto sign_message_dynamic_EXIT1;

   err=mbedtls_md_hmac(
      info_sha,
      (const unsigned char *)sha256, 32,
      (const unsigned char *)message, message_size,
      (unsigned char *)*signature
   );

   CLEAR_SHA256_DGST(sha256)

   if (err) {
      memset(*signature, 0, *signature_size);

sign_message_dynamic_EXIT1:
      free(*signature);
      *signature=NULL;
   }

   return err;
}

int
cauth_str_to_hex(
   uint8_t *hex_stream,
   char *str,
   size_t len
)
{
   char ch;
   size_t i;

   if (!len)
      if (!(len=strlen(str)))
         return -1;

   if (len&1)
      return -2;

   for (i=0;i<len;i++) {
      ch=str[i];

      if (ch>'f')
         return 1;

      if (ch<'0')
         return 2;

      ch-='0';

      if (ch>9) {
         if (ch&0x30) {

            if ((ch&0x30)==0x20)
               return 4;

            ch&=0x0F;

            ch+=9;

            if (ch<10)
               return 5;
            if (ch>15)
               return 6;

         } else
            return 3;
      }

      (i&1)?(hex_stream[i>>1]|=(uint8_t)ch):(hex_stream[i>>1]=(uint8_t)(ch<<4));
   }

   return 0;
}

#define TC_BUF_SZ 72

const uint8_t buf_cmp1_dummy[TC_BUF_SZ] =
  {
    0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0,
    0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0,
    0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0,
    0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0,
    0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0,
    0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0,
    0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0,
    0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0,
    0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0, 0xF0
  };

const uint8_t buf_cmp2_dummy[TC_BUF_SZ] =
  {
    0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A,
    0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A,
    0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A,
    0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A,
    0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A,
    0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A,
    0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A,
    0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A,
    0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A
  };

#ifdef VISIBLE_FOR_TEST
const uint8_t *get_buf_cmp1_dummy()
{
  return (uint8_t *)&buf_cmp1_dummy[0];
}

size_t get_buf_cmp1_dummy_size()
{
  return sizeof(buf_cmp1_dummy);
}

const uint8_t *get_buf_cmp2_dummy()
{
  return (uint8_t *)&buf_cmp2_dummy[0];
}

size_t get_buf_cmp2_dummy_size()
{
  return sizeof(buf_cmp2_dummy);
}
#endif

#ifndef VISIBLE_FOR_TEST
static
#endif
void memcpy_max(uint8_t *dst, uint8_t *src, ssize_t src_size, ssize_t max_dest_size)
{
  ssize_t diff = max_dest_size - src_size;

  while (diff > 0) {
    --diff;
    dst[(size_t)(src_size + diff)] = 0;
  }

  while (src_size > 0) {
    --src_size;
    dst[(size_t)src_size] = src[(size_t)src_size];
  }
}

#ifndef VISIBLE_FOR_TEST
static
#endif
bool time_const_compare(uint8_t *cmp1, ssize_t cmp1_sz, uint8_t *cmp2, ssize_t cmp2_sz)
{
  bool compare = true;

  uint8_t buf_cmp1[TC_BUF_SZ];
  uint8_t buf_cmp2[TC_BUF_SZ];

  ssize_t size = (ssize_t)sizeof(buf_cmp1);
  ssize_t cmp_sz = (cmp1_sz <= cmp2_sz)?cmp1_sz:cmp2_sz;

  if (cmp_sz > 0 && cmp_sz <= size) {
    memcpy_max(buf_cmp1, cmp1, cmp_sz, size);
    memcpy_max(buf_cmp2, cmp2, cmp_sz, size);
  } else {
    memcpy_max(buf_cmp1, (uint8_t *)buf_cmp1_dummy, size, size);
    memcpy_max(buf_cmp2, (uint8_t *)buf_cmp2_dummy, size, size);
  }

  do {
    --size;
    compare &= (buf_cmp1[size] == buf_cmp2[size]);
  } while (size > 0);

  memset(buf_cmp2, 0, sizeof(buf_cmp2));
  memset(buf_cmp1, 0, sizeof(buf_cmp1));

  return (compare) && (cmp1_sz == cmp2_sz);
}

#undef TC_BUF_SZ

CAUTH_VERIFY_CODE_ERR
cauth_verify_message_with_err(
   uint8_t *signature, size_t signature_size,
   int alg_type,
   uint8_t *key, size_t key_size,
   uint8_t *message, size_t message_size
)
{
   int err;
   uint8_t *signature_verify;
   size_t signature_verify_size;

   if (sign_message_dynamic(
      (void **)&signature_verify, &signature_verify_size,
      (mbedtls_md_type_t)alg_type, key, key_size,
      message, message_size
   )) return CAUTH_VERIFY_SIGNATURE_ERR;

   err=CAUTH_VERIFY_INVALID;

   if (time_const_compare(signature_verify, signature_verify_size, signature, signature_size))
      err=CAUTH_VERIFY_OK;

   memset(signature_verify, 0, signature_verify_size);
   free(signature_verify);

   return err;
}

inline
CAUTH_BOOL
cauth_verify_message(
   uint8_t *signature, size_t signature_size,
   int alg_type,
   uint8_t *key, size_t key_size,
   uint8_t *message, size_t message_size
)
{
   return (cauth_verify_message_with_err(
      signature, signature_size,
      alg_type,
      key, key_size,
      message, message_size
   )==CAUTH_VERIFY_OK);
}

inline void cauth_random_attach(fn_rand function)
{
   _fn_rand=function;
}

inline void cauth_random_detach()
{
   _fn_rand=NULL;
}

inline CAUTH_BOOL cauth_random(uint8_t *ptr, size_t ptr_size, int *fd, void *ctx)
{
   return ((_fn_rand!=NULL)&&(_fn_rand(ptr, ptr_size, fd, ctx)==0));
}

const char _cauth_rnd_1[]={
   'a', 'b', 'c', 'd', 'e', 'f', 'g', '\\', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
   '9', 'Y', ':', 'Z', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
   'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '^', ';', '<', '=', '>', '?',
   '1', 'Q', '2', 'R', '3', 'S', '4', 'T', '5', 'U', '6', 'V', '7', 'W', '8', 'X',
   '`', 'p', 'a', 'q', 'b', 'r', 'c', 's', 'd', 't', 'e', 'u', 'f', 'v', 'g', 'w',
   '!', 'A', '[', 'B', '#', 'C', '$', 'D', '%', 'E', '&', 'F', ']', 'G', '(', 'H',
   'h', 'x', 'i', 'y', 'j', 'z', 'k', '{', 'l', '|', 'm', '}', 'n', '~', 'o', '_',
   ')', 'I', '*', 'J', '+', 'K', ',', 'L', '-', 'M', '.', 'N', '/', 'O', '0', 'P'
};

_Static_assert(sizeof(_cauth_rnd_1)==128, "_cauth_rnd_1 wrong size");

static
const char *generate_key_dynamic_util(size_t *key_size, int alg, CAUTH_BOOL double_key, int *fd, void *ctx)
{
   uint16_t u16_sz;
   size_t sz;
   char *p;
   const char *res;

   if (!_fn_rand)
      return NULL;

   switch (alg) {
      case ALG_SHA1_DEFAULT:
         u16_sz=20;
         break;

      case ALG_SHA256:
         u16_sz=32;
         break;

      case ALG_SHA512:
         u16_sz=64;
         break;
      default:
         return NULL;
   }

   if (!(res=malloc(sz=(2*((size_t)(double_key)?u16_sz<<=1:u16_sz)+1))))
      return NULL;

   if (cauth_random((uint8_t *)(p=(char *)res), sz, fd, ctx)) {

      sz=(size_t)(u16_sz);

      if (key_size)
         *key_size=sz;

      p[sz++]=0;

      do {
         *p=(char)_cauth_rnd_1[(size_t)((*(p+sz)&0x70)|((*p)&0x0F))];
         p++;
      } while (--u16_sz);

      return res;

   }

   free((void *)res);
   return NULL;
}

inline
const char *generate_key_dynamic(int alg, int *fd, void *ctx)
{
   return generate_key_dynamic_util(NULL, alg, TRUE, fd, ctx);
}

#define CLEAR_AND_FREE(p, s) \
   memset(p, 0, s);\
   free(p);

inline
const char *generate_totp_key_dynamic(size_t *totp_key_size, int alg, CAUTH_BOOL is_base32, int *fd, void *ctx)
{

   size_t sz1, sz2;
   char
      *value=(char *)generate_key_dynamic_util(&sz1, alg, FALSE, fd, ctx),
      *res;

   if (totp_key_size)
      *totp_key_size=0;

   if (!value)
      return NULL;

   if (is_base32) {
      if ((res=malloc(cyoBase32EncodeGetLength(sz2=sz1)))) {
         if (!(sz1=cyoBase32Encode(res, (const void *)value, sz1))) {
            free(res);
            res=NULL;
         }
      }
      CLEAR_AND_FREE(value, sz2)
   } else
      res=value;

   if (totp_key_size)
      *totp_key_size=sz1;

   return (const char *)res;
}
