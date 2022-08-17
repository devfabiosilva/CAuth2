#define _GNU_SOURCE
#include <stdio.h>
#include <stdarg.h>
#include <cstring/cstring.h>

#define CSTRING_MAGIC       (uint64_t)0x2d618d7e854823a1
#define CSTRING_ARRAY_MAGIC (uint64_t)0x65293a175b5de5c4

#define _CSTRING_ARRAY_MAX_NUMBER_OF_ELEMENTS_PER_BLOCK 128
_Static_assert(
    (_CSTRING_ARRAY_MAX_NUMBER_OF_ELEMENTS_PER_BLOCK>2)&&((_CSTRING_ARRAY_MAX_NUMBER_OF_ELEMENTS_PER_BLOCK&1)==0),
    "Incoerence _CSTRING_ARRAY_MAX_NUMBER_OF_ELEMENTS_PER_BLOCK"
);

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
CSTRING *newstr_duplicate_util(const char *source, size_t str_sz)
{
    CSTRING *cstr;
    size_t sz_tmp1, sz_tmp2;

    CSTR_ALIGN(sz_tmp1, (2*str_sz));

    CREATESTR(cstr, sz_tmp2=(sz_tmp1+sizeof(*cstr)))

    cstr->magic=CSTRING_MAGIC;
    cstr->ctype=STRING_CONST_SELF_CONTAINED;
    cstr->header_description=NULL; // For a while
    cstr->size=(uint64_t)sz_tmp2;

    CSTR_COPY_SELF_CONTAINED_DUPLICATED(str_sz, sz_tmp1)

    return cstr;    
}

static
CSTRING *newstr_dyn_or_const_util(const char *source, size_t str_sz, int32_t ctype)
{
    CSTRING *cstr;

    CREATESTR(cstr, sizeof(*cstr))

    cstr->magic=CSTRING_MAGIC;
    cstr->ctype=ctype;
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
        if (!(cstr=newstr_dyn_or_const_util((const char *)str, (size_t)size, STRING_DYNAMIC)))
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
CSTRING *newstrconst(const char *source)
{
    return newstr_dyn_or_const_util(source, strlen(source), STRING_CONST);
}

inline
CSTRING *anewstr(const char *source)
{
    return newstr_dyn_or_const_util(source, strlen(source), STRING_DYNAMIC);
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
        sz_tmp1, // Aligned s1 + s2 (Always > sz_tmp2 if is STRING_CONST_SELF_CONTAINED)
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

        free_str(&cstr_tmp);

        if (cstr_tmp==NULL)
            return -3;

        return -4;
    }

    if ((*dest)==source) {
        if (!(cstr_tmp=newstr_duplicate_util(source->string, source->string_size)))
            return -5;

        free_str(dest);

        if (*dest==NULL) {
            (*dest)=cstr_tmp;
            return 0;
        }

        free_str(&cstr_tmp);

        if (cstr_tmp)
            return -7;

        return -6;
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

#define _FREE_CSTR_CTYPE \
    switch ((*cstr)->ctype) { \
        case STRING_DYNAMIC: \
            free((void *)(*cstr)->string); \
        case STRING_CONST: \
        case STRING_CONST_SELF_CONTAINED: \
            free(*cstr); \
            *cstr=NULL; \
    }

void free_str(CSTRING **cstr)
{
    if (((*cstr)!=NULL)&&((*cstr)->magic==CSTRING_MAGIC))
        _FREE_CSTR_CTYPE
}

#define CSTRING_ARRAY_INITIAL_ARRAY_SIZE sizeof(((CSTRING_ARRAY *)NULL)->cstring_objects)*_CSTRING_ARRAY_MAX_NUMBER_OF_ELEMENTS_PER_BLOCK
#define CSTRING_BLOCK_SIZE CSTRING_ARRAY_INITIAL_ARRAY_SIZE

CSTRING_ARRAY *new_cstring_array()
{
    #define CSTRING_ARRAY_NEW_OBJ_SIZE sizeof(CSTRING_ARRAY)+CSTRING_ARRAY_INITIAL_ARRAY_SIZE
    #define C_STRING_HEADER_ARRAY_INIT(cstr_array_obj) \
        cstr_array_obj->magic=CSTRING_ARRAY_MAGIC; \
        cstr_array_obj->ctype=STRING_ARRAY; \
        memset(cstr_array_obj->pad1, 0, sizeof(cstr_array_obj->pad1)); \
        cstr_array_obj->header_description=NULL; \
        cstr_array_obj->size=CSTRING_ARRAY_NEW_OBJ_SIZE;

    #define C_STRING_ARRAY_INIT(cstr_array_obj) \
        cstr_array_obj->element_index=C_STR_ARRAY_UNITIALIZED; \
        cstr_array_obj->element_index_pointer=C_STR_ARRAY_UNITIALIZED; \
        memset(cstr_array_obj->pad2, 0, sizeof(cstr_array_obj->pad2)); \
        cstr_array_obj->total_string_size=0; \
        cstr_array_obj->total_cstring_objects_size=0; \
        cstr_array_obj->total_size=CSTRING_ARRAY_NEW_OBJ_SIZE; \
        memset((void *)(cstr_array_obj->cstring_objects=_CSTRING_ARRAY_PTR_SELF_CONTAINED(cstr_array_obj)), 0, CSTRING_ARRAY_INITIAL_ARRAY_SIZE);

    CSTRING_ARRAY *cstr_array=malloc(CSTRING_ARRAY_NEW_OBJ_SIZE);

    if (!cstr_array)
        return NULL;

    C_STRING_HEADER_ARRAY_INIT(cstr_array)

    C_STRING_ARRAY_INIT(cstr_array)

    return cstr_array;

    #undef C_STRING_ARRAY_INIT
    #undef C_STRING_HEADER_ARRAY_INIT
    #undef CSTRING_ARRAY_NEW_OBJ_SIZE
}

int c_add_string_to_array(CSTRING_ARRAY **cstr_array_object, CSTRING *cstring)
{
    size_t new_size, offset;
    int32_t element_index;
    CSTRING_ARRAY *cstr_array_ptr;

    if (cstring==NULL)
        return 60;

    if (C_STR_ARRAY_UNITIALIZED>(element_index=(*cstr_array_object)->element_index))
        return 61;

    new_size=(((size_t)(++element_index))+2)*sizeof(((CSTRING_ARRAY *)NULL)->cstring_objects)+sizeof(**cstr_array_object);

    if ((*cstr_array_object)->size>=new_size) {
        offset=0;
        cstr_array_ptr=(*cstr_array_object);
    } else if ((
        cstr_array_ptr=realloc(*cstr_array_object, 
        (new_size=(((size_t)(*cstr_array_object)->size)+(offset=CSTRING_BLOCK_SIZE))))
    )) {
        cstr_array_ptr->size=(uint64_t)new_size;
        cstr_array_ptr->cstring_objects=_CSTRING_ARRAY_PTR_SELF_CONTAINED(cstr_array_ptr);
        (*cstr_array_object)=cstr_array_ptr;
    } else
        return 62;

    cstr_array_ptr->element_index=element_index;
    cstr_array_ptr->total_string_size+=cstring->string_size;

    if (cstring->ctype==STRING_CONST_SELF_CONTAINED)
        cstr_array_ptr->total_cstring_objects_size+=(uint64_t)(new_size=(size_t)cstring->size);
    else
        cstr_array_ptr->total_cstring_objects_size+=(uint64_t)(new_size=(size_t)(cstring->string_size+cstring->size+1));

    cstr_array_ptr->total_size+=(uint64_t)(new_size+offset);
    cstr_array_ptr->cstring_objects[(size_t)element_index]=cstring;
    cstr_array_ptr->cstring_objects[(size_t)(++element_index)]=NULL;

    return 0;
}

CSTRING *cstring_array_index(CSTRING_ARRAY *cstr_array_object, int32_t index)
{
    if ((cstr_array_object!=NULL)&&(cstr_array_object->element_index>=index)&&(index>-1))
        return cstr_array_object->cstring_objects[index];

    return NULL;
}

CSTRING *cstring_array_next(CSTRING_ARRAY *cstr_array_object)
{
    if ((cstr_array_object->element_index)>(cstr_array_object->element_index_pointer)) {
        if (cstr_array_object->element_index_pointer>=C_STR_ARRAY_UNITIALIZED)
            return cstr_array_object->cstring_objects[(size_t)(++cstr_array_object->element_index_pointer)];

        cstr_array_object->element_index_pointer=cstr_array_object->element_index;
    }

    return NULL;
}

CSTRING *cstring_array_previous(CSTRING_ARRAY *cstr_array_object)
{
    if (cstr_array_object->element_index_pointer>0) {
        if ((cstr_array_object->element_index)>=(cstr_array_object->element_index_pointer))
            return cstr_array_object->cstring_objects[(size_t)(--cstr_array_object->element_index_pointer)];

        cstr_array_object->element_index_pointer=C_STR_ARRAY_UNITIALIZED;
    }

    return NULL;
}

inline
int32_t cstring_array_num_elements(CSTRING_ARRAY *cstr_array_object)
{
    return (cstr_array_object->element_index+1);
}

void free_cstring_array(CSTRING_ARRAY **cstr_array_object)
{
    CSTRING **cstr;
    if ((*cstr_array_object!=NULL)&&((*cstr_array_object)->magic==CSTRING_ARRAY_MAGIC)&&((*cstr_array_object)->ctype==STRING_ARRAY)) {
        cstr=(*cstr_array_object)->cstring_objects;

        while (*cstr) {
            _FREE_CSTR_CTYPE
            cstr++;
        }

        free((void *)*cstr_array_object);
        *cstr_array_object=NULL;
    }
}

#undef CSTRING_BLOCK_SIZE
#undef CSTRING_ARRAY_INITIAL_ARRAY_SIZE
#undef _FREE_CSTR_CTYPE
#undef NEW_EMPTY_CSTR
#undef CREATESTR
#undef CSTRING_MAGIC
