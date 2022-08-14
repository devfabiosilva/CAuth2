#ifndef CSTRING_H
 #define CSTRING_H

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

enum ctype_e {
    STRING_CONST=1,
    STRING_CONST_SELF_CONTAINED,
    STRING_DYNAMIC,
    STRING_ARRAY
};

#define _CSTRING_ALIGN_SIZE (size_t)16

#define C_OBJECT_HEADER \
    uint64_t magic; \
    int32_t ctype; \
    uint8_t pad1[4]; \
    const char *header_description; \
    uint64_t size;

typedef struct cstring_t {
    C_OBJECT_HEADER
    uint64_t string_size;
    char *string;
} __attribute__((aligned(_CSTRING_ALIGN_SIZE))) CSTRING;

_Static_assert(sizeof(CSTRING)==(3*_CSTRING_ALIGN_SIZE), "Error align CSTRING");
_Static_assert(sizeof(uint64_t)>=sizeof(size_t), "Arch error");
_Static_assert(sizeof(CSTRING)==offsetof(CSTRING, string)+sizeof(((CSTRING *)NULL)->string), "Error align string");

#define C_STR_ARRAY_UNITIALIZED (int32_t)-1
typedef struct cstring_array_t {
    C_OBJECT_HEADER
    int32_t element_index;
    uint8_t pad2[4+8];
    uint64_t total_string_size;
    uint64_t total_cstring_objects_size;
    uint64_t total_size;
    CSTRING **cstring_objects;
} __attribute__((aligned(_CSTRING_ALIGN_SIZE))) CSTRING_ARRAY;

_Static_assert(sizeof(CSTRING_ARRAY)==(5*_CSTRING_ALIGN_SIZE), "Error align CSTRING_ARRAY");
_Static_assert(sizeof(CSTRING_ARRAY)==offsetof(CSTRING_ARRAY, cstring_objects)+sizeof(((CSTRING_ARRAY *)NULL)->cstring_objects), "Error align string array");

#define CSTR_ALIGN(d, s) \
    d=s+1;\
    if (d&(_CSTRING_ALIGN_SIZE-1)) { \
        d&=(~(_CSTRING_ALIGN_SIZE-1)); \
        d+=_CSTRING_ALIGN_SIZE; \
    }

#define _CSTR_PTR_SELF_CONTAINED(ptr) \
    (char *)(((char *)ptr)+offsetof(CSTRING, string)+sizeof(((CSTRING *)0)->string))

#define _CSTRING_ARRAY_PTR_SELF_CONTAINED(ptr) \
    (CSTRING **)(((uint8_t *)ptr)+offsetof(CSTRING_ARRAY, cstring_objects)+sizeof(((CSTRING_ARRAY *)0)->cstring_objects))

#define CSTR_COPY_SELF_CONTAINED(size, size_aligned) \
    cstr->string_size=(uint64_t)size; \
    cstr->string=_CSTR_PTR_SELF_CONTAINED(cstr); \
    if (size) \
        memcpy(cstr->string, source, size); \
    \
    memset(&cstr->string[size], 0, size_aligned-size);

#define CSTR_COPY_SELF_CONTAINED_DUPLICATED(size, size_aligned) \
    cstr->string_size=(uint64_t)(2*size); \
    cstr->string=_CSTR_PTR_SELF_CONTAINED(cstr); \
    if (size) {\
        memcpy(cstr->string, source, size); \
        memcpy(&cstr->string[size], source, size);\
    } \
    \
    memset(&cstr->string[cstr->string_size], 0, size_aligned-cstr->string_size);

#define CSTR_COPY_DYNAMIC \
    cstr->string_size=(uint64_t)str_sz; \
    cstr->string=(char *)source;

CSTRING *newstr(const char *);
CSTRING *newstr_fmt(const char *, ...);
CSTRING *newstrconst(const char *);
CSTRING *anewstr(const char *);
CSTRING *cstrcpy(CSTRING *);
int cstrconcat(CSTRING **, CSTRING *);
size_t cstrlen(CSTRING *);
const char *cstr_get(CSTRING *);
void free_str(CSTRING **);

CSTRING_ARRAY *new_cstring_array();
int c_add_string_to_array(CSTRING_ARRAY **, CSTRING *);
CSTRING *cstring_array_index(CSTRING_ARRAY *, int32_t);
void free_cstring_array(CSTRING_ARRAY **);

#endif
