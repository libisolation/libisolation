#include <vmm.h>
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include "list.h"

static int kvm = -1;
static int kvm_run_size = -1;

struct vmm_vm {
  int vmfd;
  struct list_head cpus;
};

struct vmm_cpu {
  struct list_head head;
  int vcpufd;
  struct kvm_run *run;
};

int
vmm_create(vmm_vm_t *vm)
{
  static pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;
  int ret;

  if (kvm < 0) {
    pthread_mutex_lock(&mut);
    if (kvm < 0) {
      kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    }
    pthread_mutex_unlock(&mut);
    if (kvm < 0) {
      return VMM_ENOTSUP;
    }
  }

  /* check API version */
  if ((ret = ioctl(kvm, KVM_GET_API_VERSION, NULL)) < 0)
    return -errno;
  if (ret != 12)
    return VMM_ENOTSUP;

  int vmfd;
  if ((vmfd = ioctl(kvm, KVM_CREATE_VM, 0UL)) < 0)
    return -errno;

  struct vmm_vm *p = malloc(sizeof *p);
  if (p == 0) {
    close(vmfd);
    return VMM_ENOMEM;
  }
  p->vmfd = vmfd;
  INIT_LIST_HEAD(&p->cpus);

  *vm = p;

  return 0;
}

int
vmm_destroy(vmm_vm_t vm)
{
  struct list_head *p, *n;
  list_for_each_safe (p, n, &vm->cpus) {
    vmm_cpu_destroy(vm, list_entry(p, struct vmm_cpu, head));
  }
  close(vm->vmfd);
  free(vm);
  return 0;
}

int
vmm_memory_map(vmm_vm_t vm, vmm_uvaddr_t uva, vmm_gpaddr_t gpa, size_t size, int prot)
{
  int valid_prots = PROT_READ | PROT_WRITE | PROT_EXEC;

  if (prot & ~valid_prots)
    return VMM_EINVAL;
  if ((prot & PROT_EXEC) == 0)
    return VMM_EINVAL;

  struct kvm_userspace_memory_region region = {
    .slot = 0, // FIXME
    .flags = (prot & PROT_WRITE) == 0 ? KVM_MEM_READONLY : 0,
    .guest_phys_addr = gpa,
    .memory_size = size,
    .userspace_addr = (uint64_t)uva,
  };
  int ret;

  if ((ret = ioctl(vm->vmfd, KVM_SET_USER_MEMORY_REGION, &region)) < 0)
    return -errno;

  return 0;
}

int
vmm_cpu_create(vmm_vm_t vm, vmm_cpu_t *cpu)
{
  static pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;

  int vcpufd;
  if ((vcpufd = ioctl(vm->vmfd, KVM_CREATE_VCPU, 0UL)) < 0)
    return -errno;

  /* Map the shared kvm_run structure and following data. */
  if (kvm_run_size < 0) {
    int e = VMM_ENOTSUP;
    pthread_mutex_lock(&mut);
    if (kvm_run_size < 0) {
      kvm_run_size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);
      e = -errno;
    }
    pthread_mutex_unlock(&mut);
    if (kvm_run_size < 0) {
      return e;
    }
  }
  struct kvm_run *run;
  if ((run = mmap(NULL, kvm_run_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0)) == MAP_FAILED)
    return -errno;
  assert(run != 0);

  struct vmm_cpu *p = malloc(sizeof *p);
  if (p == 0) {
    munmap(run, kvm_run_size);
    close(vcpufd);
    return VMM_ENOMEM;
  }
  p->vcpufd = vcpufd;
  p->run = run;
  list_add(&p->head, &vm->cpus);

  *cpu = p;

  return 0;
}

int
vmm_cpu_destroy(vmm_vm_t vm, vmm_cpu_t cpu)
{
  if (munmap(cpu->run, kvm_run_size) < 0)
    return -errno;
  close(cpu->vcpufd);
  list_del(&cpu->head);
  free(cpu);
  return 0;
}

int
vmm_cpu_run(vmm_vm_t vm, vmm_cpu_t cpu)
{
  if (ioctl(cpu->vcpufd, KVM_RUN, NULL) < 0)
    return -errno;
  return 0;
}

/*

struct kvm_regs {
  __u64 rax, rbx, rcx, rdx;
  __u64 rsi, rdi, rsp, rbp;
  __u64 r8,  r9,  r10, r11;
  __u64 r12, r13, r14, r15;
  __u64 rip, rflags;
};

struct kvm_segment {
  __u64 base;
  __u32 limit;
  __u16 selector;
  __u8  type;
  __u8  present, dpl, db, s, l, g, avl;
  __u8  unusable;
  __u8  padding;
};

struct kvm_dtable {
  __u64 base;
  __u16 limit;
  __u16 padding[3];
};

struct kvm_sregs {
  struct kvm_segment cs, ds, es, fs, gs, ss;
  struct kvm_segment tr, ldt;
  struct kvm_dtable gdt, idt;
  __u64 cr0, cr2, cr3, cr4, cr8;
  __u64 efer;
  __u64 apic_base;
  __u64 interrupt_bitmap[(KVM_NR_INTERRUPTS + 63) / 64];
};

*/

#define EXTRACT(value, l, r) (((value) & ((1 << (l + 1)) - 1)) >> r)

#define SET_AR(ar, value) do {\
  ar.type    = EXTRACT(value, 11, 8);\
  ar.present = EXTRACT(value, 15, 15);\
  ar.dpl     = EXTRACT(value, 14, 13);\
  ar.db      = EXTRACT(value, 22, 22);\
  ar.s       = EXTRACT(value, 12, 12);\
  ar.l       = EXTRACT(value, 21, 21);\
  ar.g       = EXTRACT(value, 23, 23);\
  ar.avl     = EXTRACT(value, 20, 20);\
} while (0)

int
vmm_cpu_set_register(vmm_vm_t vm, vmm_cpu_t cpu, vmm_x64_reg_t reg, uint64_t value)
{
  static struct kvm_regs regs;
  static struct kvm_sregs sregs;

  if (ioctl(cpu->vcpufd, KVM_GET_REGS, &regs) < 0)
    return -errno;
  if (ioctl(cpu->vcpufd, KVM_GET_SREGS, &sregs) < 0)
    return -errno;

  switch (reg) {
#define CASE(reg, field) case reg: (field) = value; break
  CASE(VMM_X64_RIP, regs.rip);
  CASE(VMM_X64_RFLAGS, regs.rflags);
  CASE(VMM_X64_RAX, regs.rax);
  CASE(VMM_X64_RBX, regs.rbx);
  CASE(VMM_X64_RCX, regs.rcx);
  CASE(VMM_X64_RDX, regs.rdx);
  CASE(VMM_X64_RSI, regs.rsi);
  CASE(VMM_X64_RDI, regs.rdi);
  CASE(VMM_X64_RSP, regs.rsp);
  CASE(VMM_X64_RBP, regs.rbp);
  CASE(VMM_X64_R8, regs.r8);
  CASE(VMM_X64_R9, regs.r9);
  CASE(VMM_X64_R10, regs.r10);
  CASE(VMM_X64_R11, regs.r11);
  CASE(VMM_X64_R12, regs.r12);
  CASE(VMM_X64_R13, regs.r13);
  CASE(VMM_X64_R14, regs.r14);
  CASE(VMM_X64_R15, regs.r15);

  CASE(VMM_X64_CS, sregs.cs.selector);
  CASE(VMM_X64_CS_BASE, sregs.cs.base);
  CASE(VMM_X64_CS_LIMIT, sregs.cs.limit);
  case VMM_X64_CS_AR:
    SET_AR(sregs.cs, value);
    break;
  CASE(VMM_X64_SS, sregs.ss.selector);
  CASE(VMM_X64_SS_BASE, sregs.ss.base);
  CASE(VMM_X64_SS_LIMIT, sregs.ss.limit);
  case VMM_X64_SS_AR:
    SET_AR(sregs.ss, value);
    break;
  CASE(VMM_X64_DS, sregs.ds.selector);
  CASE(VMM_X64_DS_BASE, sregs.ds.base);
  CASE(VMM_X64_DS_LIMIT, sregs.ds.limit);
  case VMM_X64_DS_AR:
    SET_AR(sregs.ds, value);
    break;
  CASE(VMM_X64_ES, sregs.es.selector);
  CASE(VMM_X64_ES_BASE, sregs.es.base);
  CASE(VMM_X64_ES_LIMIT, sregs.es.limit);
  case VMM_X64_ES_AR:
    SET_AR(sregs.es, value);
    break;
  CASE(VMM_X64_FS, sregs.fs.selector);
  CASE(VMM_X64_FS_BASE, sregs.fs.base);
  CASE(VMM_X64_FS_LIMIT, sregs.fs.limit);
  case VMM_X64_FS_AR:
    SET_AR(sregs.fs, value);
    break;
  CASE(VMM_X64_GS, sregs.gs.selector);
  CASE(VMM_X64_GS_BASE, sregs.gs.base);
  CASE(VMM_X64_GS_LIMIT, sregs.gs.limit);
  case VMM_X64_GS_AR:
    SET_AR(sregs.gs, value);
    break;
  CASE(VMM_X64_LDTR, sregs.ldt.selector);
  CASE(VMM_X64_LDT_BASE, sregs.ldt.base);
  CASE(VMM_X64_LDT_LIMIT, sregs.ldt.limit);
  case VMM_X64_LDT_AR:
    SET_AR(sregs.ldt, value);
    break;
  CASE(VMM_X64_TR, sregs.tr.selector);
  CASE(VMM_X64_TSS_BASE, sregs.tr.base);
  CASE(VMM_X64_TSS_LIMIT, sregs.tr.limit);
  case VMM_X64_TSS_AR:
    SET_AR(sregs.tr, value);
    break;
  CASE(VMM_X64_IDT_BASE, sregs.idt.base);
  CASE(VMM_X64_IDT_LIMIT, sregs.idt.limit);
  CASE(VMM_X64_GDT_BASE, sregs.gdt.base);
  CASE(VMM_X64_GDT_LIMIT, sregs.gdt.limit);

  CASE(VMM_X64_CR0, sregs.cr0);
  case VMM_X64_CR1:
    return VMM_EINVAL;
  CASE(VMM_X64_CR2, sregs.cr2);
  CASE(VMM_X64_CR3, sregs.cr3);
  CASE(VMM_X64_CR4, sregs.cr4);
  case VMM_X64_DR0:
  case VMM_X64_DR1:
  case VMM_X64_DR2:
  case VMM_X64_DR3:
  case VMM_X64_DR4:
  case VMM_X64_DR5:
  case VMM_X64_DR6:
  case VMM_X64_DR7:
  case VMM_X64_TPR:
  case VMM_X64_XCR0:
    assert(false); // TODO
  default:
    assert(false);
#undef CASE
  }

  if (ioctl(cpu->vcpufd, KVM_SET_REGS, &regs) < 0)
    return -errno;
  if (ioctl(cpu->vcpufd, KVM_SET_SREGS, &sregs) < 0)
    return -errno;

  return 0;
}

#define GET_AR(ar, value) do {\
    uint32_t x = 0;\
    x |= ar.g << 23;\
    x |= ar.db << 22;\
    x |= ar.l << 21;\
    x |= ar.avl << 20;\
    x |= ar.present << 15;\
    x |= ar.dpl << 13;\
    x |= ar.s << 12;\
    x |= ar.type << 8;\
    *value = x;\
  } while (0)

int
vmm_cpu_get_register(vmm_vm_t vm, vmm_cpu_t cpu, vmm_x64_reg_t reg, uint64_t *value)
{
  static struct kvm_regs regs;
  static struct kvm_sregs sregs;

  if (ioctl(cpu->vcpufd, KVM_GET_REGS, &regs) < 0)
    return -errno;
  if (ioctl(cpu->vcpufd, KVM_GET_SREGS, &sregs) < 0)
    return -errno;

  switch (reg) {
#define CASE(reg, field) case reg: *value = (field); break
  CASE(VMM_X64_RIP, regs.rip);
  CASE(VMM_X64_RFLAGS, regs.rflags);
  CASE(VMM_X64_RAX, regs.rax);
  CASE(VMM_X64_RBX, regs.rbx);
  CASE(VMM_X64_RCX, regs.rcx);
  CASE(VMM_X64_RDX, regs.rdx);
  CASE(VMM_X64_RSI, regs.rsi);
  CASE(VMM_X64_RDI, regs.rdi);
  CASE(VMM_X64_RSP, regs.rsp);
  CASE(VMM_X64_RBP, regs.rbp);
  CASE(VMM_X64_R8, regs.r8);
  CASE(VMM_X64_R9, regs.r9);
  CASE(VMM_X64_R10, regs.r10);
  CASE(VMM_X64_R11, regs.r11);
  CASE(VMM_X64_R12, regs.r12);
  CASE(VMM_X64_R13, regs.r13);
  CASE(VMM_X64_R14, regs.r14);
  CASE(VMM_X64_R15, regs.r15);

  CASE(VMM_X64_CS, sregs.cs.selector);
  CASE(VMM_X64_CS_BASE, sregs.cs.base);
  CASE(VMM_X64_CS_LIMIT, sregs.cs.limit);
  case VMM_X64_CS_AR:
    GET_AR(sregs.cs, value);
    break;
  CASE(VMM_X64_SS, sregs.ss.selector);
  CASE(VMM_X64_SS_BASE, sregs.ss.base);
  CASE(VMM_X64_SS_LIMIT, sregs.ss.limit);
  case VMM_X64_SS_AR:
    GET_AR(sregs.ss, value);
    break;
  CASE(VMM_X64_DS, sregs.ds.selector);
  CASE(VMM_X64_DS_BASE, sregs.ds.base);
  CASE(VMM_X64_DS_LIMIT, sregs.ds.limit);
  case VMM_X64_DS_AR:
    GET_AR(sregs.ds, value);
    break;
  CASE(VMM_X64_ES, sregs.es.selector);
  CASE(VMM_X64_ES_BASE, sregs.es.base);
  CASE(VMM_X64_ES_LIMIT, sregs.es.limit);
  case VMM_X64_ES_AR:
    GET_AR(sregs.es, value);
    break;
  CASE(VMM_X64_FS, sregs.fs.selector);
  CASE(VMM_X64_FS_BASE, sregs.fs.base);
  CASE(VMM_X64_FS_LIMIT, sregs.fs.limit);
  case VMM_X64_FS_AR:
    GET_AR(sregs.fs, value);
    break;
  CASE(VMM_X64_GS, sregs.gs.selector);
  CASE(VMM_X64_GS_BASE, sregs.gs.base);
  CASE(VMM_X64_GS_LIMIT, sregs.gs.limit);
  case VMM_X64_GS_AR:
    GET_AR(sregs.gs, value);
    break;
  CASE(VMM_X64_LDTR, sregs.ldt.selector);
  CASE(VMM_X64_LDT_BASE, sregs.ldt.base);
  CASE(VMM_X64_LDT_LIMIT, sregs.ldt.limit);
  case VMM_X64_LDT_AR:
    GET_AR(sregs.ldt, value);
    break;
  CASE(VMM_X64_TR, sregs.tr.selector);
  CASE(VMM_X64_TSS_BASE, sregs.tr.base);
  CASE(VMM_X64_TSS_LIMIT, sregs.tr.limit);
  case VMM_X64_TSS_AR:
    GET_AR(sregs.tr, value);
    break;
  CASE(VMM_X64_IDT_BASE, sregs.idt.base);
  CASE(VMM_X64_IDT_LIMIT, sregs.idt.limit);
  CASE(VMM_X64_GDT_BASE, sregs.gdt.base);
  CASE(VMM_X64_GDT_LIMIT, sregs.gdt.limit);

  CASE(VMM_X64_CR0, sregs.cr0);
  case VMM_X64_CR1:
    return VMM_EINVAL;
  CASE(VMM_X64_CR2, sregs.cr2);
  CASE(VMM_X64_CR3, sregs.cr3);
  CASE(VMM_X64_CR4, sregs.cr4);
  case VMM_X64_DR0:
  case VMM_X64_DR1:
  case VMM_X64_DR2:
  case VMM_X64_DR3:
  case VMM_X64_DR4:
  case VMM_X64_DR5:
  case VMM_X64_DR6:
  case VMM_X64_DR7:
  case VMM_X64_TPR:
  case VMM_X64_XCR0:
    assert(false); // TODO
  default:
    assert(false);
#undef CASE
  }
  return 0;
}

int
vmm_cpu_get_msr(vmm_vm_t vm, vmm_cpu_t cpu, uint32_t msr, uint64_t *value)
{
  char buf[offsetof(struct kvm_msrs, entries) + sizeof(struct kvm_msr_entry)];
  struct kvm_msrs *kmsrs = (struct kvm_msrs *) buf;

  kmsrs->nmsrs = 1;
  kmsrs->entries[0].index = msr;
  int r;
  if ((r = ioctl(cpu->vcpufd, KVM_GET_MSRS, kmsrs)) < 0)
    return -errno;
  *value = kmsrs->entries[0].data;
  return 0;
}

int
vmm_cpu_set_msr(vmm_vm_t vm, vmm_cpu_t cpu, uint32_t msr, uint64_t value)
{
  char buf[offsetof(struct kvm_msrs, entries) + sizeof(struct kvm_msr_entry)];
  struct kvm_msrs *kmsrs = (struct kvm_msrs *) buf;

  kmsrs->nmsrs = 1;
  kmsrs->entries[0].index = msr;
  kmsrs->entries[0].data = value;
  int r;
  if ((r = ioctl(cpu->vcpufd, KVM_SET_MSRS, kmsrs)) < 0)
    return -errno;
  return 0;
}

int
vmm_cpu_get_state(vmm_vm_t vm, vmm_cpu_t cpu, int id, uint64_t *value)
{
  switch (id) {
  case VMM_CTRL_EXIT_REASON:
    switch (cpu->run->exit_reason) {
    case KVM_EXIT_HLT: *value = VMM_EXIT_HLT; break;
    case KVM_EXIT_IO:  *value = VMM_EXIT_IO; break;
    default:
      *value = VMM_EXIT_REASONS_MAX;
      fprintf(stderr, "%d", cpu->run->exit_reason);
      assert(false);
      return -1;
    }
    break;
  default:
    return VMM_EINVAL;
  }
  return 0;
}
