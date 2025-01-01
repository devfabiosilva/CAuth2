#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int gen_rand_no_entropy_util(uint8_t *output, size_t output_len, int *fd, void *ctx)
{
    ssize_t bytes_read;

    if (!output)
        return -3;

    if (!output_len)
        return -2;

    if (((size_t)(bytes_read=read(*fd, (void *)output, output_len)))==output_len)
        return 0;

    return -2;
}

//-1 Fail
// 0 Success
int test_vector(uint8_t *v, size_t v_sz, uint8_t c)
{
    if (!v_sz)
        return -1;

    do {
        if (v[--v_sz]!=c)
            return -1;
    } while (v_sz > 0);

    return 0;
}

#define PG_ALIGN 16

void debug_dump(uint8_t *data, size_t data_sz)
{
  size_t i;
  int page;

  if (!data) {
    fprintf(stderr, "\ndebug_dump: NULL data");
    return;
  }

  if (!data_sz) {
    fprintf(stderr, "\ndebug_dump: Empty data");
    return;
  }

  page=0;

  for (i=0;i<data_sz;i++) {
    if ((i&(PG_ALIGN-1))==0) {
      fprintf(stdout, "\n\tpage %03d: ", page);
      page+=PG_ALIGN;
    } else if ((i&((PG_ALIGN>>1)-1))==0)
      fprintf(stdout, "  ");

    fprintf(stdout, " %02x", data[i]);
  }

  fprintf(stdout, "\n");

}

void debug_dump_ascii(uint8_t *data, size_t data_sz)
{
  size_t i;
  int page;
  uint8_t c;

  if (!data) {
    fprintf(stderr, "debug_dump_ascii: NULL data");
    return;
  }

  if (!data_sz) {
    fprintf(stderr, "debug_dump_ascii: Empty data");
    return;
  }

  page=0;

  for (i=0;i<data_sz;i++) {
    if ((i&(PG_ALIGN-1))==0) {
      fprintf(stdout, "\n\tpage %03d: ", page);
      page+=PG_ALIGN;
    } else if ((i&((PG_ALIGN>>1)-1))==0)
      fprintf(stdout, "  ");

    if (((c=data[i])<0x21) || (c>0x7E))
      fprintf(stdout, "  %02X ", c);
    else
      fprintf(stdout, " '%c' ", (char)c);
  }

  fprintf(stdout, "\n");

}

int is_vec_content_eq(
  uint8_t *a, size_t a_sz,
  uint8_t *b, size_t b_sz
)
{

  if (a==b)
    return (a_sz==b_sz);

  if (!a)
    return 0;

  if (!b)
    return 0;

  if (a_sz!=b_sz)
    return 0;

  if (!a_sz)
    return 1;

  return (memcmp(a, b, a_sz)==0);
}

#undef PG_ALIGN

