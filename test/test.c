#include <isolation.h>
#include <stdio.h>
#include <assert.h>

int main()
{
  isl_handle_t h = isl_open("test.so");

  assert(h >= 0);

  //isl_sym_t s = isl_sym(h, "test");

  //isl_free(s);

  isl_close(h);
}
