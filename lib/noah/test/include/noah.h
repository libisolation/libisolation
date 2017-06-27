typedef unsigned long uint64_t;
typedef unsigned long size_t;
typedef long ssize_t;

uint64_t syscall(uint64_t num, uint64_t rdi, uint64_t rsi, uint64_t rdx)
{
  uint64_t ret;
  asm("syscall"
      : "=rax" (ret)
      : "0" (num), "D" (rdi), "S" (rsi), "d" (rdx)
      : "cc", "memory", "r11", "rcx"
      );
  return ret;
}

#define SYS_read 0
#define SYS_write 1
#define SYS_open 2
#define SYS_close 3
#define SYS_exit 60
#define SYS_rename 82

#define O_RDONLY 0

ssize_t read(int fd, void *buf, size_t count)
{
  return syscall(SYS_read, fd, (uint64_t)buf, count);
}

ssize_t write(int fd, const void *buf, size_t count)
{
  return syscall(SYS_write, fd, (uint64_t)buf, count);
}

int open(const char *path, int flags)
{
  return syscall(SYS_open, (uint64_t)path, flags, 0);
}

int rename(const char *oldpath, const char *newpath)
{
  return syscall(SYS_rename, (uint64_t)oldpath, (uint64_t)newpath, 0);
}

int close(unsigned int fd)
{
  return syscall(SYS_close, fd, 0, 0);
}

void _exit(int status)
{
  syscall(SYS_exit, status, 0, 0);
  __builtin_unreachable();
}

int _main(int argc, char **argv)
{
  typedef int (*main_t)(int, char **, char **);
  int main();
  _exit(((main_t)main)(argc, argv, argv + argc + 1));
}

size_t strlen(const char *str)
{
  const char *s;
  for (s = str; *s; s++);
  return s - str;
}

int strcmp(const char *s, const char *t) {
  while (*s && *s == *t) s++, t++;
  return *s - *t;
}
