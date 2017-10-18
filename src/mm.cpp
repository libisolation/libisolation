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
#include <asm/processor-flags.h>
#include <asm/msr-index.h>

#include <vmm.h>
#include "elf.h"
#include "types.hpp"
#include "mm.hpp"

static const gaddr_t user_addr_max = 0x0000007fc0000000ULL;

gaddr_t
kmap(vmm_vm_t vm, void *ptr, size_t size, int flags)
{
  static uint64_t noah_kern_brk = user_addr_max;

  assert((size & 0xfff) == 0);
  assert(((uint64_t) ptr & 0xfff) == 0);

  //record_region(&vkern_mm, ptr, noah_kern_brk, size, hv_mflag_to_linux_mprot(flags), -1, -1, 0);
  flags |= PROT_EXEC;  // non-PROT_EXEC is not supported on kvm
  vmm_memory_map(vm, ptr, noah_kern_brk, size, flags);
  noah_kern_brk += size;

  return noah_kern_brk - size;
}


uint64_t pml4[NR_PAGE_ENTRY] __page_aligned = {
  [0] = PTE_U | PTE_W | PTE_P,
};
static gaddr_t pml4_ptr;

uint64_t pdp[NR_PAGE_ENTRY] __page_aligned = {
  /* straight mapping */
#include "pdp"
};

void
init_page(vmm_vm_t vm, vmm_cpu_t cpu)
{
  pml4_ptr = kmap(vm, pml4, 0x1000, PROT_READ | PROT_WRITE);
  pml4[0] |= kmap(vm, pdp, 0x1000, PROT_READ | PROT_WRITE) & 0x000ffffffffff000ul;

  vmm_cpu_set_register(vm, cpu, VMM_X64_CR3, pml4_ptr);
  vmm_cpu_set_register(vm, cpu, VMM_X64_CR4, X86_CR4_PAE);
  vmm_cpu_set_register(vm, cpu, VMM_X64_CR0, X86_CR0_PG | X86_CR0_PE | X86_CR0_NE);
  vmm_cpu_set_register(vm, cpu, VMM_X64_EFER, EFER_LME | EFER_LMA | EFER_NX);
}

struct segment_desc {
  unsigned low_limit : 16;
  unsigned low_base : 16;
  unsigned mid_base : 8;
  unsigned type : 4;
  unsigned s : 1;
  unsigned dpl : 2;
  unsigned present : 1;
  unsigned high_limit : 4;
  unsigned avl : 1;
  unsigned long_mode : 1;
  unsigned db : 1;
  unsigned granularity : 1;
  unsigned high_base : 8;
};

static uint16_t
segdesc_to_ar(const struct segment_desc *segdesc)
{
  // a little bit redundant definiton to make the structure of
  // access rights easier to understand
  union ar {
    struct {
      unsigned type : 4;
      unsigned s : 1;
      unsigned dpl : 2;
      unsigned present : 1;
      unsigned reserved : 4;
      unsigned avl : 1;
      unsigned long_mode : 1;
      unsigned db : 1;
      unsigned granularity : 1;
    } ar_struct;
    uint16_t packed;
  } ar;

  assert(sizeof(struct segment_desc) == sizeof(uint64_t));
  ar.packed = 0xffff & (*((uint64_t *)segdesc) >> 40);
  ar.ar_struct.reserved = 0;
  return ar.packed;
}

void
init_segment(vmm_vm_t vm, vmm_cpu_t cpu)
{
  static const int DSCTYPE_CODE_DATA = 1;
  static const int SEGTYPE_RW        = 2;
  static const int SEGTYPE_RE        = 10;
  static const int SEG_NULL = 0;
  static const int SEG_CODE = 1;
  static const int SEG_DATA = 2;

  static struct segment_desc gdt[] __page_aligned = {{0}, {0}, {0}};
  gdt[SEG_CODE].type = SEGTYPE_RE;
  gdt[SEG_CODE].s = DSCTYPE_CODE_DATA;
  gdt[SEG_CODE].long_mode = 1;
  gdt[SEG_CODE].present = 1;
  gdt[SEG_DATA].type = SEGTYPE_RW;
  gdt[SEG_DATA].s = DSCTYPE_CODE_DATA;
  gdt[SEG_DATA].long_mode = 1;
  gdt[SEG_DATA].present = 1;

  gaddr_t gdt_ptr = kmap(vm, (void *)gdt, 0x1000, PROT_READ | PROT_WRITE);

  assert(sizeof(struct segment_desc) == sizeof(uint64_t));

  uint16_t code_ar = segdesc_to_ar(&gdt[SEG_CODE]);
  uint16_t data_ar = segdesc_to_ar(&gdt[SEG_DATA]);

  vmm_cpu_set_register(vm, cpu, VMM_X64_GDT_BASE, gdt_ptr);
  vmm_cpu_set_register(vm, cpu, VMM_X64_GDT_LIMIT, 3 * 8 - 1);

  vmm_cpu_set_register(vm, cpu, VMM_X64_CS, 0x8);
  vmm_cpu_set_register(vm, cpu, VMM_X64_CS_BASE, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_CS_LIMIT, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_CS_AR, code_ar);

  vmm_cpu_set_register(vm, cpu, VMM_X64_DS, 0x10);
  vmm_cpu_set_register(vm, cpu, VMM_X64_DS_BASE, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_DS_LIMIT, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_DS_AR, data_ar);

  vmm_cpu_set_register(vm, cpu, VMM_X64_ES, 0x10);
  vmm_cpu_set_register(vm, cpu, VMM_X64_ES_BASE, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_ES_LIMIT, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_ES_AR, data_ar);

  vmm_cpu_set_register(vm, cpu, VMM_X64_FS, 0x10);
  vmm_cpu_set_register(vm, cpu, VMM_X64_FS_BASE, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_FS_LIMIT, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_FS_AR, data_ar);

  vmm_cpu_set_register(vm, cpu, VMM_X64_GS, 0x10);
  vmm_cpu_set_register(vm, cpu, VMM_X64_GS_BASE, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_GS_LIMIT, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_GS_AR, data_ar);

  vmm_cpu_set_register(vm, cpu, VMM_X64_SS, 0x10);
  vmm_cpu_set_register(vm, cpu, VMM_X64_SS_BASE, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_SS_LIMIT, 0);
  vmm_cpu_set_register(vm, cpu, VMM_X64_SS_AR, data_ar);
}
