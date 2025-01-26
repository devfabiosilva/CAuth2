#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <cauth2.h>
#include <fcntl.h>
#include <unistd.h>

typedef struct {
   PyObject_HEAD
   const char *hmac_secret_key_dyn;
   size_t hmac_secret_key_size;
   int hmac_alg_type;
   const char *totp_secret_key_dyn;
   size_t totp_secret_key_size;
   int totp_alg_type;
} C_RAW_DATA_OBJ;

#define SET_CONST(val) \
  {#val, val},
struct algAuthConst_t {
   const char *name;
   int value;
} ALG_AUTH_CONST[] = {
  SET_CONST(ALG_SHA1)
  SET_CONST(ALG_SHA256)
  SET_CONST(ALG_SHA512)
  {NULL}
};

struct entropy_type_t {
   const char *name;
   int value;
} ENTROPY_TYPE[] = {
  SET_CONST(ENTROPY_TYPE_PARANOIC)
  SET_CONST(ENTROPY_TYPE_EXCELENT)
  SET_CONST(ENTROPY_TYPE_GOOD)
  SET_CONST(ENTROPY_TYPE_NOT_ENOUGH)
  SET_CONST(ENTROPY_TYPE_NOT_RECOMENDED)
  {NULL}
};
#undef SET_CONST

#ifdef P_DEBUG
 #define PANEL_DEBUG(std, ...) \
    fprintf(std, __VA_ARGS__);
#else
 #define PANEL_DEBUG(std, ...)
#endif

#define PANEL_ERROR(err_msg, errNumber) \
   {\
      PyErr_SetString(PyExc_Exception, err_msg);\
      return errNumber;\
   }

#define ERR_CANT_SHOW_ERR (char *)"Fail on parse error format"
static const char *error_msg_dynamic(const char *fmt, ...)
{
   int err;
   char *msg_fmt;
   va_list args;

   va_start(args, fmt);
   err=vasprintf(&msg_fmt, fmt, args);
   va_end(args);

   if (err>=0)
      return (const char *)msg_fmt;

   return ERR_CANT_SHOW_ERR;
}

#define PANEL_ERROR_FMT(errNumber, valueFmt, ...) \
   {\
      char *_p=(char *)error_msg_dynamic(valueFmt, __VA_ARGS__); \
      PyErr_SetString(PyExc_Exception, _p);\
      if (_p!=ERR_CANT_SHOW_ERR)\
         free(_p);\
      return errNumber;\
   }

#define CLEAR_AND_FREE(__p, __s) \
   memset((void *)__p, 0, __s); \
   free((void *)__p); \
   __p=NULL;

#define CLEAR_AND_FREE_SAFE(__p, __s) \
   if (__p) { \
      CLEAR_AND_FREE(__p, __s) \
   }

static PyObject *c_raw_data_obj_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
   C_RAW_DATA_OBJ *self;

   if (!(self=(C_RAW_DATA_OBJ *)type->tp_alloc(type, 0)))
      PANEL_ERROR("C_RAW_DATA_OBJ error", NULL)

   PANEL_DEBUG(stdout, "New object created at %p\n", self)

   return (PyObject *)self;
}

static int c_raw_data_obj_init(C_RAW_DATA_OBJ *self, PyObject *args, PyObject *kwds)
{
   int err;
   const char *errMsg;
   char
      *kwlist[] = {"hmacSecretKey", "totpSecretKey", "hmacAlgType", "totpAlgType", NULL},
      *hmacSecretKey, *totpSecretKey=NULL;

   self->hmac_secret_key_dyn=NULL;
   self->totp_secret_key_dyn=NULL;
   self->hmac_alg_type=ALG_SHA256;
   self->totp_alg_type=ALG_SHA1;

   if (!PyArg_ParseTupleAndKeywords(
      args, kwds, "s|sII", kwlist,
      &hmacSecretKey, &totpSecretKey, &self->hmac_alg_type, &self->totp_alg_type
   )) PANEL_ERROR("Error on parse on init", 11)

   if (!(self->hmac_secret_key_size=strlen(hmacSecretKey)))
      PANEL_ERROR("Empty HMAC secret key", 12)

   if (!(self->hmac_secret_key_dyn=malloc(++(self->hmac_secret_key_size))))
      PANEL_ERROR("Could not alloc memory to store secret key", 4)

   strncpy((char *)self->hmac_secret_key_dyn, hmacSecretKey, self->hmac_secret_key_size--);

   if (totpSecretKey) {
      if ((err=check_base32_oauth_key_valid(
            NULL, totpSecretKey,
            self->totp_secret_key_size=strlen(totpSecretKey), self->totp_alg_type
      ))) {
         errMsg="Empty Auth2 TOTP Base32 secret key or C function check_base32_oauth_key_valid() error";
         goto totpSecretKey_ERROR;
      }

      if (!(self->totp_secret_key_dyn=malloc(++(self->totp_secret_key_size)))) {
         err=15;
         errMsg="Could not alloc memory to store Auth2 TOTP";
         goto totpSecretKey_ERROR;
      }

      strncpy((char *)self->totp_secret_key_dyn, totpSecretKey, self->totp_secret_key_size--);
   }

   return 0;

totpSecretKey_ERROR:
   memset((void *)self->hmac_secret_key_dyn, 0, self->hmac_secret_key_size);
   free((void *)self->hmac_secret_key_dyn);
   self->hmac_secret_key_dyn=NULL;
   PANEL_ERROR(errMsg, err)
}

static void c_raw_data_obj_dealloc(C_RAW_DATA_OBJ *self)
{
   PANEL_DEBUG(stdout, "Dealloc secret key\n")
   CLEAR_AND_FREE_SAFE(self->hmac_secret_key_dyn, self->hmac_secret_key_size)
   PANEL_DEBUG(stdout, "Dealloc totp secret key\n")
   CLEAR_AND_FREE_SAFE(self->totp_secret_key_dyn, self->totp_secret_key_size)
   PANEL_DEBUG(stdout, "Dealloc object\n")
   Py_TYPE(self)->tp_free((PyObject *)self);
   PANEL_DEBUG(stdout, "Free object\n")
}

static PyObject *get_auth_totp(C_RAW_DATA_OBJ *self, PyObject *args, PyObject *kwds)
{
   int err;
   uint32_t c_result;

   if (self->totp_secret_key_dyn) {
      if ((err=cauth_2fa_auth_code(
         &c_result,
         self->totp_alg_type,
         (uint8_t *)self->totp_secret_key_dyn,
         self->totp_secret_key_size,
         TRUE, 0, 30, NULL, 6
      ))) PANEL_ERROR_FMT(NULL, "C error @ cauth_2fa_auth_code with error code = %d", err)
   } else
      PANEL_ERROR("Could not get Auth TOTP. Please initilize with Base32 Auth secret key", NULL)

   return PyLong_FromLong((long int)c_result);
}

static PyObject *sign_message(C_RAW_DATA_OBJ *self, PyObject *args, PyObject *kwds)
{
   int err;
   static char *kwlist[] = {"messageStr", NULL};
   char *strMsg;
   static void *signed_message_ptr;
   size_t signed_message_size;
   PyObject *ret;

   if (!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &strMsg))
      PANEL_ERROR("Can't parse message to be assigned", NULL)

   if ((err=sign_message_dynamic(
      (void **)&signed_message_ptr, &signed_message_size,
      self->hmac_alg_type,
      (uint8_t *)self->hmac_secret_key_dyn, self->hmac_secret_key_size,
      (uint8_t *)strMsg, strlen(strMsg)
   ))) PANEL_ERROR_FMT(NULL, "Sign message error @ sign_message_dynamic with err = %d", err)

   ret=Py_BuildValue("y#", signed_message_ptr, signed_message_size);
   CLEAR_AND_FREE(signed_message_ptr, signed_message_size)

   if (ret)
      return ret;

   PANEL_ERROR("Error. Can't convert binary to string", NULL)
}

static PyObject *c_buildDate(C_RAW_DATA_OBJ *self, PyObject *args, PyObject *kwds)
{
   return Py_BuildValue("s", cauth_buildDate());
}

static PyObject *c_getVersion(C_RAW_DATA_OBJ *self, PyObject *args, PyObject *kwds)
{
   return Py_BuildValue("s", cauth_getVersion());
}

static PyObject *generateKeyUtil(
  PyObject *args, PyObject *kwds, bool isTOTP
)
{
   static char
      *kwlist[] = {"algType", "entropyType", "timeoutInSeconds", "randomGeneratorDevice", NULL};

   uint8_t *result;
   size_t result_sz;
   const char *randomGeneratorDevice, *functionName, *buildValue;
   long int alg, entropy;
   signed long int timeoutInSeconds;
   int err;
   PyObject *ret;

   alg=ALG_SHA512;
   entropy=ENTROPY_TYPE_GOOD;
   timeoutInSeconds=DEFAULT_TIMEOUT_IN_SECOND;
   randomGeneratorDevice=NULL;

   if (!PyArg_ParseTupleAndKeywords(args, kwds, "|llLs", kwlist, &alg, &entropy, &timeoutInSeconds, &randomGeneratorDevice))
      PANEL_ERROR("Can't parse algorithm type", NULL)

   if (timeoutInSeconds < 1)
     PANEL_ERROR("Invalid timeout", NULL)

   if (!check_entropy_value(entropy))
     PANEL_ERROR("Invalid entropy type", NULL)

   if (isTOTP) {
     functionName = "generate_totp_key_dynamic";
     buildValue = "s#";
     err=generate_totp_key_dynamic((const char **)&result, &result_sz, (int)alg, (uint32_t)entropy, (uint64_t)timeoutInSeconds, randomGeneratorDevice);
   } else {
     buildValue = "y#";
     functionName = "generate_key_dynamic";
     err=generate_key_dynamic(&result, &result_sz, (int)alg, (uint32_t)entropy, (uint64_t)timeoutInSeconds, randomGeneratorDevice);
   }

   if (err)
     PANEL_ERROR_FMT(NULL, "Generate key error @ %s with err = %d", functionName, err)

   ret=Py_BuildValue(buildValue, result, result_sz);

   clear_rnd_and_free(&result, result_sz, randomGeneratorDevice);

   if (ret)
      return ret;

   PANEL_ERROR("Error. generate key to string", NULL)
}

static PyObject *c_generatekey(C_RAW_DATA_OBJ *self, PyObject *args, PyObject *kwds)
{
  return generateKeyUtil(args, kwds, false);
}

static PyObject *c_generatetopkey(C_RAW_DATA_OBJ *self, PyObject *args, PyObject *kwds)
{
  return generateKeyUtil(args, kwds, true);
}

static PyObject *c_decodetotpkeywithalg(C_RAW_DATA_OBJ *self, PyObject *args, PyObject *kwds)
{
   int err;
   static char *kwlist[] = {"totpkey", "algorithm", NULL};
   char *totpkey;
   Py_ssize_t totpkey_sz;
   long int alg;
   uint8_t *out;
   size_t out_sz;
   PyObject *ret;

   if (!PyArg_ParseTupleAndKeywords(args, kwds, "s#l", kwlist, &totpkey, &totpkey_sz, &alg))
      PANEL_ERROR("c_decodetotpkeywithalg: Can't parse totpkey to decode", NULL)

   if ((err=decode_totp_key_with_alg_check_dynamic(&out, &out_sz, (int)alg, (const char *)totpkey, (ssize_t)totpkey_sz)))
     PANEL_ERROR_FMT(NULL, "c_decodetotpkeywithalg: Could not decode totp key. Err = %d", err)

   ret=Py_BuildValue("y#", out, (Py_ssize_t)out_sz);
   clear_rnd_and_free(&out, out_sz, NULL);

   if (ret)
      return ret;

   PANEL_ERROR("c_decodetotpkeywithalg: Can't convert C byte array to Python 3 byte array", NULL)
}

static PyObject *c_encodetotpkeywithalg(C_RAW_DATA_OBJ *self, PyObject *args, PyObject *kwds)
{
   int err;
   static char *kwlist[] = {"value", "algorithm", NULL};
   uint8_t *in;
   Py_ssize_t in_sz;
   long int alg;
   const char *out;
   size_t out_sz;
   PyObject *ret;

   if (!PyArg_ParseTupleAndKeywords(args, kwds, "y#l", kwlist, &in, &in_sz, &alg))
      PANEL_ERROR("c_encodetotpkeywithalg: Can't parse value to decode", NULL)

   if ((err=encode_totp_key_with_alg_check_dynamic(&out, &out_sz, (int)alg, (const uint8_t *)in, (size_t)in_sz)))
     PANEL_ERROR_FMT(NULL, "c_encodetotpkeywithalg: Could not encode totp key with alg. Err = %d", err)

   ret=Py_BuildValue("s#", out, (Py_ssize_t)out_sz);
   clear_rnd_and_free((uint8_t **)&out, out_sz, NULL);

   if (ret)
      return ret;

   PANEL_ERROR("c_encodetotpkeywithalg: Can't convert C char array to Python 3 string", NULL)
}

static PyMethodDef panelauth_methods[] = {
    {"getAuthTotp", (PyCFunction)get_auth_totp, METH_NOARGS, "Get current TOTP authentication code with given initialized secret."},
    {"signMessage", (PyCFunction)sign_message, METH_VARARGS|METH_KEYWORDS, "Signs a message with a given private key"},
    {NULL}
};

static PyTypeObject PANEL_AUTH_Type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name="Panel Auth",
    .tp_doc="This module implements AUTH2 and HMAC signature for PLC Control panel and IoT devices",
    .tp_basicsize=sizeof(C_RAW_DATA_OBJ),
    .tp_itemsize=0,
    .tp_flags=Py_TPFLAGS_DEFAULT|Py_TPFLAGS_BASETYPE,
    .tp_new=c_raw_data_obj_new,
    .tp_init=(initproc)c_raw_data_obj_init,
    .tp_dealloc=(destructor)c_raw_data_obj_dealloc,
    .tp_methods=panelauth_methods
};

static PyModuleDef PANEL_AUTH_module = {
    PyModuleDef_HEAD_INIT,
    .m_name="PANEL_AUTH module",
    .m_doc="PLC panel / IoT AUTH2 and HMAC protocol modules for Python 3 using C library",
    .m_size=-1,
};

static PyMethodDef py_cauth2_modules_functions[] = {
    {"buildDate", (PyCFunction)c_buildDate, METH_NOARGS, "Get C Auth2 current build date"},
    {"getVersion", (PyCFunction)c_getVersion, METH_NOARGS, "Get C Auth2 current version"},
    {"genKey", (PyCFunction)c_generatekey, METH_VARARGS|METH_KEYWORDS, "Generates key given algorithm type"},
    {"genTOTPKey", (PyCFunction)c_generatetopkey, METH_VARARGS|METH_KEYWORDS, "Generates TOTP key given algorithm type"},
    {"decodeTOTPKeyWithAlg", (PyCFunction)c_decodetotpkeywithalg, METH_VARARGS|METH_KEYWORDS, "Decodes Base 32 key with given algorithm"},
    {"encodeTOTPKeyWithAlg", (PyCFunction)c_encodetotpkeywithalg, METH_VARARGS|METH_KEYWORDS, "Encodes messages to Base 32 with given algorithm"},
    {NULL}
};

PyMODINIT_FUNC PyInit_panelauth(void)
{
   PyObject *m;
   struct algAuthConst_t *algConst;
   struct entropy_type_t *entropy_type;

   PANEL_DEBUG(stdout, "Check is panel is ready\n")
   if (PyType_Ready(&PANEL_AUTH_Type)<0)
      PANEL_ERROR("\n\"Can't initialize module Panel Auth\"\n", NULL)

   PANEL_DEBUG(stdout, "Creating module ...\n")
   if (!(m=PyModule_Create(&PANEL_AUTH_module)))
      PANEL_ERROR("\nCannot create module \"PANEL_AUTH_module\"\n", NULL)

   PANEL_DEBUG(stdout, "Module %p created.\n Adding module objects", m);
   if (PyModule_AddObjectRef(m, "create", (PyObject *) &PANEL_AUTH_Type)<0) {
      Py_DECREF(m);
      PANEL_ERROR("\nCannot create module \"panelauth\" from \"PANEL_AUTH_Type\"\n", NULL)
   }

   PANEL_DEBUG(stdout, "Adding functions ...");
   if (PyModule_AddFunctions(m, py_cauth2_modules_functions)<0) {
     Py_DECREF(m);
     PANEL_ERROR("\nCannot add function to module\n", NULL)
   }

   PANEL_DEBUG(stdout, "Object added\nAdding constants ...\n");

   algConst=ALG_AUTH_CONST;

   while (algConst->name) {
      if (PyModule_AddIntConstant(m, algConst->name, (long int)algConst->value)) {
         Py_DECREF(m);
         PANEL_ERROR("Could not add alg const values", NULL)
      }

      algConst++;
   }

   entropy_type=ENTROPY_TYPE;

   while (entropy_type->name) {
      if (PyModule_AddIntConstant(m, entropy_type->name, (long int)entropy_type->value)) {
         Py_DECREF(m);
         PANEL_ERROR("Could not add entropy const values", NULL)
      }

      entropy_type++;
   }

   return m;
}

