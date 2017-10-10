#include "../include/vmm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <asm/processor-flags.h>
#include <asm/msr-index.h>

#define PG_V  1
#define PG_RW (1 << 1)
#define PG_U  (1 << 2)
#define PG_PS (1 << 7)

const uint64_t ADDR_PT4 = 0x2000;
const uint64_t ADDR_PT3 = 0x3000;
const uint64_t ADDR_PT2 = 0x4000;

const uint64_t ADDR_GTD = 0x5000;

const uint64_t ADDR_ENTRY = 0x6000;

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

#define DSCTYPE_CODE_DATA  1
#define SEGTYPE_RW         2
#define SEGTYPE_RE         10

#define DESC_NULL 0
#define DESC_CODE 1
#define DESC_DATA 2


uint16_t segdesc_to_ar(const struct segment_desc *segdesc)
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

void init_segment64(vmm_vm_t vm, vmm_cpu_t cpu, char *mem)
{
  int err;

  static const struct segment_desc gdt[] = {
    [DESC_NULL] = {0},
    [DESC_CODE] = {
      .high_limit = 0, .low_limit = 0,
      .type = 11, .s = DSCTYPE_CODE_DATA, .long_mode = 1,
      .dpl = 0, .present = 1, .db = 0, .granularity = 0, 
    },
    [DESC_DATA] = {
      .high_limit = 0, .low_limit = 0,
      .type = 3, .s = DSCTYPE_CODE_DATA, .long_mode = 1,
      .dpl = 0, .present = 1, .db = 0, .granularity = 0,
    }
  };

  memcpy(mem + ADDR_GTD, gdt, sizeof gdt);
  assert(sizeof(struct segment_desc) == sizeof(uint64_t));

  uint16_t code_ar = segdesc_to_ar(&gdt[DESC_CODE]);
  uint16_t data_ar = segdesc_to_ar(&gdt[DESC_DATA]);

  vmm_cpu_set_register(vm, cpu, VMM_X64_GDT_BASE, ADDR_GTD);
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


void init_page64(vmm_vm_t vm, vmm_cpu_t cpu, char *mem)
{
  const int page_size = 0x1000;
  uint64_t *pt4 = (uint64_t *)(mem + ADDR_PT4);
  uint64_t *pt3 = (uint64_t *)((char *)pt4 + page_size);
  uint64_t *pt2 = (uint64_t *)((char *)pt3 + page_size);

  for (int i = 0; i < 512; i++) {
    pt4[i] = (uint64_t)ADDR_PT3;
    pt4[i] |= PG_V | PG_RW | PG_U;
    pt3[i] = (uint64_t)ADDR_PT2;
    pt3[i] |= PG_V | PG_RW | PG_U;
    pt2[i] = i * (2 * 1024 * 1024);
    pt2[i] |= PG_V | PG_RW | PG_PS | PG_U;
  }
  
  vmm_cpu_set_register(vm, cpu, VMM_X64_CR3, ADDR_PT4);
  vmm_cpu_set_register(vm, cpu, VMM_X64_CR4, X86_CR4_PAE);
  vmm_cpu_set_register(vm, cpu, VMM_X64_CR0, X86_CR0_PG | X86_CR0_PE | X86_CR0_NE);
  vmm_cpu_set_register(vm, cpu, VMM_X64_EFER, EFER_LME | EFER_LMA | EFER_NX);
}

int main()
{
  const uint8_t code[] = {
     0x48, 0xc7, 0xc0, 0x61, 0x00, 0x00, 0x00,    // movq    $'a',%rax
     0xe7, 0x01,                                  // outl    %eax,$0x1
     0xf4,                                        // hlt
  };

  vmm_vm_t vm;
  int err = vmm_create(&vm);
  assert(err == 0);

  vmm_cpu_t cpu;
  err = vmm_cpu_create(vm, &cpu);
  assert(err == 0);
  

  char *mem = mmap(NULL, 0x100000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  bzero(mem, 0x100000);
  err = vmm_memory_map(vm, mem, 0, 0x100000, PROT_READ | PROT_WRITE | PROT_EXEC);
  assert(err == 0);

  init_page64(vm, cpu, mem);
  init_segment64(vm, cpu, mem);

  vmm_cpu_set_register(vm, cpu, VMM_X64_RFLAGS, 0x2);
  vmm_cpu_set_register(vm, cpu, VMM_X64_RIP, ADDR_ENTRY);

  memcpy(mem + ADDR_ENTRY, code, sizeof(code));

  /* Repeatedly run code and handle VM exits. */
  while (1) {
    int ret = vmm_cpu_run(vm, cpu);
    assert(ret == 0);
    uint64_t exit_reason, value;
    vmm_cpu_get_register(vm, cpu, VMM_X64_RIP, &value);
    ret = vmm_cpu_get_state(vm, cpu, VMM_CTRL_EXIT_REASON, &exit_reason);
    assert(ret == 0);
    switch (exit_reason) {
    case VMM_EXIT_FAIL_ENTRY:
      puts("KVM_EXIT_FAIL_ENTRY");
      return 0;
    case VMM_EXIT_HLT:
      puts("KVM_EXIT_HLT");
      return 0;
    case VMM_EXIT_IO:
      ret = vmm_cpu_get_register(vm, cpu, VMM_X64_RAX, &value);
      assert(ret == 0);
      printf("from guest '%c'\n", (char) value);
      break;
    default:
     ret = vmm_cpu_get_register(vm, cpu, VMM_X64_RIP, &value);
     assert(ret == 0);
     fprintf(stderr, "ip = 0x%lx\n", value);
     fprintf(stderr, "exit_reason = 0x%lx", exit_reason);
     abort();
    }
  }
}
