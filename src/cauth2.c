#include <cauth2_dev.h>
#include <cyoencode/CyoDecode.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>
#include <stdio.h>
#include <version.h>
#include <cauth2_dev.h>

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

   if ((err=mbedtls_sha256_finish(sha256, (unsigned char *)*res)))
      goto cauth_sha256_digest_EXIT;

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

   if (signature_verify_size!=signature_size) {
      err=CAUTH_VERIFY_WRONG_SIZE_ERR;
      goto cauth_veryfy_message_EXIT1;
   }

   err=CAUTH_VERIFY_INVALID;

   if (memcmp(signature_verify, signature, signature_verify_size)==0)
      err=CAUTH_VERIFY_OK;

cauth_veryfy_message_EXIT1:
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

inline uint8_t *cauth_random(uint8_t *ptr, size_t ptr_size)
{
   if ((_fn_rand!=NULL)&&(!_fn_rand(ptr, ptr_size)))
      return ptr;

   return NULL;
}