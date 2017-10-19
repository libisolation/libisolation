#include <isolation.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <climits>
#include <cctype>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <algorithm>

#include <vmm.h>
#include "elf.h"
#include "mm.hpp"

#define ROUNDUP(N, S) ((((N) + (S) - 1) / (S)) * (S))
typedef unsigned long ulong;

static vmm_vm_t vm;
static vmm_cpu_t cpu;

static int
load_elf(vmm_vm_t vm, Elf64_Ehdr *ehdr)
{
  assert(IS_ELF(*ehdr));

  if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
    fprintf(stderr, "not an executable file");
    return -1;
  }
  if (ehdr->e_machine != EM_X86_64) {
    fprintf(stderr, "not an x64 executable");
    return -1;
  }
  if (ehdr->e_type != ET_DYN) {
    fprintf(stderr, "not a dynamic library");
    return -1;
  }

  Elf64_Phdr *p = (Elf64_Phdr *) ((char *) ehdr + ehdr->e_phoff);

  ulong map_top = 0, map_bottom = ULONG_MAX;

#define PAGE_4KB 4096
#define PAGE_ALIGN_MASK (PAGE_4KB - 1)

  for (int i = 0; i < ehdr->e_phnum; i++) {
    if (p[i].p_type == PT_INTERP) {
      fprintf(stderr, "dynamic libraries with PT_INTERP section not supported");
      return -1;
    }
    if (p[i].p_type != PT_LOAD) {
      continue;
    }

    ulong vaddr = p[i].p_vaddr & ~PAGE_ALIGN_MASK;
    ulong offset = p[i].p_vaddr & PAGE_ALIGN_MASK;
    ulong size = ROUNDUP(p[i].p_memsz + offset, PAGE_4KB);

    map_bottom = std::max(map_bottom, vaddr);
    map_top = std::max(map_top, vaddr + size);
  }

  void *mem = mmap(0, map_top - map_bottom, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  for (int i = 0; i < ehdr->e_phnum; i++) {
    if (p[i].p_type != PT_LOAD) {
      continue;
    }

    ulong vaddr = p[i].p_vaddr & ~PAGE_ALIGN_MASK;
    ulong offset = p[i].p_vaddr & PAGE_ALIGN_MASK;
    ulong size = ROUNDUP(p[i].p_memsz + offset, PAGE_4KB);

    int prot = 0;
    if (p[i].p_flags & PF_X) prot |= PROT_EXEC;
    if (p[i].p_flags & PF_W) prot |= PROT_WRITE;
    if (p[i].p_flags & PF_R) prot |= PROT_READ;

    vmm_memory_map(vm, mem, vaddr, size, prot);

    memcpy((char *) mem + offset, (char *) ehdr + p[i].p_offset, p[i].p_filesz);
  }

  // // construct stack
  // do_mmap(STACK_TOP - STACK_SIZE, STACK_SIZE, PROT_READ | PROT_WRITE, LINUX_PROT_READ | LINUX_PROT_WRITE, LINUX_MAP_PRIVATE | LINUX_MAP_FIXED | LINUX_MAP_ANONYMOUS, -1, 0);
  // vmm_set_register(vmid, cpuid, VMM_X64_RSP, STACK_TOP);
  // vmm_set_register(vmid, cpuid, VMM_X64_RBP, STACK_TOP);

  return 0;
}

static int
do_load(vmm_vm_t vm, const char *elf_path)
{
  int fd;
  if ((fd = open(elf_path, O_RDONLY)) < 0) {
    return -1;
  }
  struct stat st;
  if (fstat(fd, &st) < 0) {
    return -1;
  }
  char *data;
  if ((data = (char *)mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
    return -1;
  }
  close(fd);

  if (! (4 <= st.st_size && memcmp(data, ELFMAG, 4) == 0)) {
    return -1;
  }
  int err;
  if ((err = load_elf(vm, (Elf64_Ehdr *) data)) < 0) {
    printf("huee");
    return err;
  }
  if (munmap(data, st.st_size) < 0) {
    return -1;
  }
  return 0;
}

isl_handle_t
isl_open(const char *filename)
{
  if (vmm_create(&vm) < 0)
    return -1;
  if (vmm_cpu_create(vm, &cpu) < 0)
    return -1;

  init_page(vm, cpu);
  init_segment(vm, cpu);
  vmm_cpu_set_register(vm, cpu, VMM_X64_RFLAGS, 0x2);

  if (do_load(vm, filename) < 0)
    return -1;

  return 0;
}

int
isl_close(isl_handle_t handle)
{
  assert(handle == 0);
  if (vmm_cpu_destroy(vm, cpu) < 0)
    return -1;
  if (vmm_destroy(vm) < 0)
    return -1;
  return 0;
}

static isl_return_t
isl_vm_run(isl_handle_t handle, void *ret)
{
  uint64_t exit_reason, rip, rax;
  int err = vmm_cpu_run(vm, cpu);
  assert(err == 0);
  vmm_cpu_get_register(vm, cpu, VMM_X64_RAX, &rax);
  vmm_cpu_get_register(vm, cpu, VMM_X64_RIP, &rip);
  vmm_cpu_get_state(vm, cpu, VMM_CTRL_EXIT_REASON, &exit_reason);
  switch (exit_reason) {
    case VMM_EXIT_FAIL_ENTRY:
      return ISL_ERROR;
    case VMM_EXIT_HLT:
      *reinterpret_cast<uint64_t *>(ret) = rax;
      return ISL_SUCCESS;
    case VMM_EXIT_IO:
      return ISL_EEXTCALL;
    default:
      fprintf(stderr, "Unsuported error\n");
      fprintf(stderr, "ip = 0x%lx\n", rip);
      fprintf(stderr, "exit_reason = 0x%lx", exit_reason);
      abort();
  }
}

isl_return_t
isl_call(isl_handle_t handle, isl_sym_t f, void *args[], void *ret)
{
  // TODO: push args

  vmm_cpu_set_register(vm, cpu, VMM_X64_RIP, f);
  return isl_vm_run(handle, ret);
}

isl_return_t
isl_resume(isl_handle_t handle, void *ret)
{
  return isl_vm_run(handle, ret);
}
