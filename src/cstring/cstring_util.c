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
    return cstr->string_size;
}

inline
CSTRING *cstrcpy(CSTRING *source)
{
    return newstr_util((const char *)source->string, (size_t)source->string_size);
}

int cstrconcat(CSTRING **dest, CSTRING *source)
{
    char *aux;
    CSTRING *realloc_dest, *cstr_tmp;
    size_t
        sz_tmp1, // Aligned s1 + s2 (Always > sz_tmp2)
        sz_tmp2, // Size = s1 + s2
        sz_tmp3; // Total CSTRING object size

    if (source->string_size==0)
        return 0;

    if ((*dest)->string_size==0) {
        if (!(cstr_tmp=cstrcpy(source)))
            return -2;
 
        free_str(dest);

        if ((*dest)==NULL) {
            *dest=cstr_tmp;
            return 0;
        }

        return -3;
    }

    CSTR_ALIGN(sz_tmp1, (sz_tmp2=((*dest)->string_size+source->string_size)));

    if (!(realloc_dest=(CSTRING *)realloc((void *)*dest, sz_tmp3=(sizeof(CSTRING)+sz_tmp1))))
        return -1;

    aux=_CSTR_PTR_SELF_CONTAINED(realloc_dest);

    if (realloc_dest->ctype==STRING_CONST_SELF_CONTAINED)
        memcpy(
            (void *)((char *)(aux+realloc_dest->string_size)),
            source->string, source->string_size
        );
    else {
        memcpy((void *)aux, realloc_dest->string, realloc_dest->string_size);
        memcpy((void *)(
            (char *)(aux+realloc_dest->string_size)
        ), source->string, source->string_size);

        if (realloc_dest->ctype==STRING_DYNAMIC)
            free(realloc_dest->string);
    }

    memset((void *)((char *)(aux+sz_tmp2)), 0, sz_tmp1-sz_tmp2);

    realloc_dest->ctype=STRING_CONST_SELF_CONTAINED;
    realloc_dest->size=sz_tmp3;
    realloc_dest->string_size=sz_tmp2;
    realloc_dest->string=aux;

    (*dest)=realloc_dest;

    return 0;
}

inline
const char *cstr_get(CSTRING *cstr)
{
    return (const char *)cstr->string;
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
