#include <isolation.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <grp.h>

// TODO: Merge to "simple_isl_call_test_asm.c" 
//       after implementing neat isl_free and isl_close

int main()
{
  struct group *kvmgid = getgrnam("kvm");
  assert(kvmgid->gr_gid == getegid());

  uint64_t ret;

  /* call a C library  */
  isl_handle_t h = isl_open("simple_c_lib.so");
  assert(h >= 0);

  isl_return_t err;
  //isl_sym_t s = isl_sym(h, "add");
  isl_sym_t s = 0x650; // Cheating. The address of "add" function
  uint64_t args[6] = {40, 2};
  err = isl_call(h, s, &args, &ret);
  assert(err == ISL_SUCCESS);
  printf("ret:%lu\n", ret);
  assert(ret == 42);

  //isl_free(s);
  isl_close(h);
}
