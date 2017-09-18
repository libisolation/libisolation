#include <isolation.h>
#include <stdio.h>
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

  //isl_sym_t s = isl_sym(h, "test");

  //isl_free(s);

  isl_close(h);
}
