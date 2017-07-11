#include <isolation.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <vmm.h>
#include "elf.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) < (b) ? (b) : (a))
#define ROUNDUP(N, S) ((((N) + (S) - 1) / (S)) * (S))
typedef unsigned long ulong;

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

    map_bottom = MIN(map_bottom, vaddr);
    map_top = MAX(map_top, vaddr + size);
  }

  void *mem = mmap(0, map_top - map_bottom, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

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
  if ((data = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
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

static vmm_vm_t vm;
static vmm_cpu_t cpu;

isl_handle_t
isl_open(const char *filename)
{
  if (vmm_create(&vm) < 0)
    return -1;
  if (vmm_cpu_create(vm, &cpu) < 0)
    return -1;

  if (do_load(vm, filename) < 0)
    return -1;

  vmm_cpu_set_register(vm, cpu, VMM_X64_RAX, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_RBX, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_RCX, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_RDX, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_RSI, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_RDI, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_R8, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_R9, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_R10, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_R11, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_R12, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_R13, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_R14, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_R15, 0);

  vmm_cpu_set_register(vm, cpu, VMM_X64_FS, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_ES, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_GS, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_DS, 0);
//  vmm_cpu_set_register(vm, cpu, VMM_X64_CS, GSEL(SEG_CODE, 0));
//  vmm_cpu_set_register(vm, cpu, VMM_X64_DS, GSEL(SEG_DATA, 0));

//  vmm_cpu_set_register(vm, cpu, VMM_X64_FS_BASE, 0);
//  vmm_cpu_set_register(vm, cpu, VMM_X64_GS_BASE, 0);

  vmm_cpu_set_register(vm, cpu, VMM_X64_LDTR, 0);

  //init_fpu();

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
