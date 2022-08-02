#include <cstring/cstring.h>

#define CREATESTR(s, size) \
    if (!(s=malloc(size))) \
        return NULL;


CSTRING *newstr(const char *source)
{
    CSTRING *cstr;
    size_t str_sz=strlen(source), sz_tmp1, sz_tmp2;

    CSTR_ALIGN(sz_tmp1, str_sz);

    CREATESTR(cstr, sz_tmp2=(sz_tmp1+sizeof(*cstr)))

    cstr->ctype=STRING_CONST_SELF_CONTAINED;
    cstr->header_description=NULL; // For a while
    cstr->size=(uint64_t)sz_tmp2;

    CSTR_COPY_SELF_CONTAINED(str_sz, sz_tmp1)

    return cstr;
}

void free_str(CSTRING **cstr)
{
    if (*cstr) {
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

#undef _CREATESTR