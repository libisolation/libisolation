#include <isolation.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <grp.h>

int main()
{
  struct group *kvmgid = getgrnam("kvm");
  assert(kvmgid->gr_gid == getegid());

  isl_handle_t h = isl_open("test.so");

  assert(h >= 0);

  uint64_t ret;
  isl_return_t err;
  //isl_sym_t s = isl_sym(h, "test");
  isl_sym_t s = 0x620; // Cheating. The address of "test" function
  err = isl_call(h, s, NULL, &ret);
  assert(err == ISL_SUCCESS);
  assert(ret == 42);

  //isl_free(s);

  isl_close(h);
}
