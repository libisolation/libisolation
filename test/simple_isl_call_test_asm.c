#include <isolation.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <grp.h>

// TODO: Merge to "simple_isl_call_test_c.c" 
//       after implementing neat isl_free and isl_close

int main()
{
  struct group *kvmgid = getgrnam("kvm");
  assert(kvmgid->gr_gid == getegid());

  uint64_t ret;

  /* call an asm library  */

  isl_handle_t h = isl_open("simple_asm_lib.so");
  assert(h >= 0);

  isl_return_t err;
  //isl_sym_t s = isl_sym(h, "test");
  isl_sym_t s = 0x620; // Cheating. The address of "test" function
  err = isl_call(h, s, NULL, &ret);
  assert(err == ISL_SUCCESS);
  printf("ret:%lu\n", ret);
  assert(ret == 42);

  //isl_free(s);
  isl_close(h);
}
