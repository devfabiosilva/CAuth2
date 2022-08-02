#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <cstring/cstring.h>

#define CSTRING_MAGIC (uint64_t)0x2d618d7e854823a1

#define CREATESTR(s, size) \
    if (!(s=malloc(size))) \
        return NULL;

#define NEW_EMPTY_CSTR newstr_util("", 0);

static
CSTRING *newstr_util(const char *source, size_t str_sz)
{
    CSTRING *cstr;
    size_t sz_tmp1, sz_tmp2;

    CSTR_ALIGN(sz_tmp1, str_sz);

    CREATESTR(cstr, sz_tmp2=(sz_tmp1+sizeof(*cstr)))

    cstr->magic=CSTRING_MAGIC;
    cstr->ctype=STRING_CONST_SELF_CONTAINED;
    cstr->header_description=NULL; // For a while
    cstr->size=(uint64_t)sz_tmp2;

    CSTR_COPY_SELF_CONTAINED(str_sz, sz_tmp1)

    return cstr;    
}

static
CSTRING *newstr_dyn_util(const char *source, size_t str_sz)
{
    CSTRING *cstr;

    CREATESTR(cstr, sizeof(*cstr))

    cstr->magic=CSTRING_MAGIC;
    cstr->ctype=STRING_DYNAMIC;
    cstr->header_description=NULL; // For a while
    cstr->size=(uint64_t)sizeof(*cstr);

    CSTR_COPY_DYNAMIC

    return cstr;    
}

inline
CSTRING *newstr(const char *source)
{
    return newstr_util(source, strlen(source));
}

CSTRING *newstr_fmt(const char *fmt, ...)
{
    int size;
    char *str;
    va_list args;
    CSTRING *cstr;

    va_start(args, fmt);
    size=vasprintf(&str, fmt, args);
    va_end(args);

    if (size>0) {
        if (!(cstr=newstr_dyn_util((const char *)str, (size_t)size)))
            free((void *)str);
        return cstr;
    }

    if (size==0) {
        free((void *)str);
        return NEW_EMPTY_CSTR
    }

    return NULL;
}

inline
size_t cstrlen(CSTRING *cstr)
{
    return cstr->size;
}

inline
CSTRING *cstrcpy(CSTRING *source)
{
    return newstr_util((const char *)source->string, (size_t)source->string_size);
}

void free_str(CSTRING **cstr)
{
    if (((*cstr)!=NULL)&&((*cstr)->magic==CSTRING_MAGIC)) {
        switch ((*cstr)->ctype) {
            case STRING_DYNAMIC:
                free((void *)(*cstr)->string);
            case STRING_CONST:
            case STRING_CONST_SELF_CONTAINED:
                free(*cstr);
                *cstr=NULL;
        }
    }
}

#undef NEW_EMPTY_CSTR
#undef CREATESTR
#undef CSTRING_MAGIC