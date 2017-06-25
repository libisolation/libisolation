#include <vmm.h>
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

static int kvm, vmfd;
static struct kvm_run *run;
static struct kvm_regs regs;
static struct kvm_sregs sregs;
static int vcpufd;

int
vmm_create(void)
{
  int ret;

  if ((kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC)) < 0)
    return VMM_ENOTSUP;

  /* check API version */
  if ((ret = ioctl(kvm, KVM_GET_API_VERSION, NULL)) < 0)
    return VMM_ERROR;
  if (ret != 12)
    return VMM_ENOTSUP;

  if ((vmfd = ioctl(kvm, KVM_CREATE_VM, 0UL)) < 0)
    return VMM_ERROR;

  return 0;
}

int
vmm_destroy(void)
{
  close(vmfd);
  close(kvm);
  return 0;
}

int
vmm_memory_map(vmm_uvaddr_t uva, vmm_gpaddr_t gpa, size_t size, vmm_memory_flags_t flags)
{
  struct kvm_userspace_memory_region region = {
    .slot = 0,
    .guest_phys_addr = gpa,
    .memory_size = size,
    .userspace_addr = (uint64_t)uva,
  };
  int ret;

  if ((ret = ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region)) < 0)
    return VMM_ERROR;

  return 0;
}

int
vmm_cpu_create(void)
{
  int mmap_size;

  if ((vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, 0UL)) < 0)
    return VMM_ERROR;

  /* Map the shared kvm_run structure and following data. */
  if ((mmap_size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL)) < 0)
    return VMM_ERROR;
  if ((run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0)) == 0)
    return VMM_ERROR;

  return 0;
}

int
vmm_cpu_destroy(void)
{
  close(vcpufd);
  run = NULL;
  return 0;
}

int
vmm_cpu_run(void)
{
  if (ioctl(vcpufd, KVM_RUN, NULL) < 0)
    return VMM_ERROR;
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

int
vmm_cpu_write_register(vmm_x64_reg_t reg, uint64_t value)
{
  if (ioctl(vcpufd, KVM_GET_REGS, &regs) < 0)
    return VMM_ERROR;
  if (ioctl(vcpufd, KVM_GET_SREGS, &sregs) < 0)
    return VMM_ERROR;

  switch (reg) {
  case VMM_X64_RIP:      regs.rip = value; break;
  case VMM_X64_RFLAGS:   regs.rflags = value; break;
  case VMM_X64_RAX:      regs.rax = value; break;
  case VMM_X64_RBX:      regs.rbx = value; break;
  case VMM_X64_RCX:      regs.rcx = value; break;
  case VMM_X64_RDX:      regs.rdx = value; break;
  case VMM_X64_RSI:      regs.rsi = value; break;
  case VMM_X64_RDI:      regs.rdi = value; break;
  case VMM_X64_RSP:      regs.rsp = value; break;
  case VMM_X64_RBP:      regs.rbp = value; break;
  case VMM_X64_R8:
  case VMM_X64_R9:
  case VMM_X64_R10:
  case VMM_X64_R11:
  case VMM_X64_R12:
  case VMM_X64_R13:
  case VMM_X64_R14:
  case VMM_X64_R15:
    assert(false);
  case VMM_X64_CS: sregs.cs.base = value; break;
  case VMM_X64_SS:
  case VMM_X64_DS:
  case VMM_X64_ES:
  case VMM_X64_FS:
  case VMM_X64_GS:
  case VMM_X64_IDT_BASE:
  case VMM_X64_IDT_LIMIT:
  case VMM_X64_GDT_BASE:
  case VMM_X64_GDT_LIMIT:
  case VMM_X64_LDTR:
  case VMM_X64_LDT_BASE:
  case VMM_X64_LDT_LIMIT:
  case VMM_X64_LDT_AR:
  case VMM_X64_TR:
  case VMM_X64_TSS_BASE:
  case VMM_X64_TSS_LIMIT:
  case VMM_X64_TSS_AR:
  case VMM_X64_CR0:
  case VMM_X64_CR1:
  case VMM_X64_CR2:
  case VMM_X64_CR3:
  case VMM_X64_CR4:
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
  default:
    assert(false);
  }

  if (ioctl(vcpufd, KVM_SET_REGS, &regs) < 0)
    return VMM_ERROR;
  if (ioctl(vcpufd, KVM_SET_SREGS, &sregs) < 0)
    return VMM_ERROR;

  return 0;
}

int
vmm_cpu_read_register(vmm_x64_reg_t reg, uint64_t *value)
{
  if (ioctl(vcpufd, KVM_GET_REGS, &regs) < 0)
    return VMM_ERROR;
  if (ioctl(vcpufd, KVM_GET_SREGS, &sregs) < 0)
    return VMM_ERROR;

  switch (reg) {
  case VMM_X64_RIP:      *value = regs.rip; break;
  case VMM_X64_RFLAGS:   *value = regs.rflags; break;
  case VMM_X64_RAX:      *value = regs.rax; break;
  case VMM_X64_RBX:      *value = regs.rbx; break;
  case VMM_X64_RCX:      *value = regs.rcx; break;
  case VMM_X64_RDX:      *value = regs.rdx; break;
  case VMM_X64_RSI:      *value = regs.rsi; break;
  case VMM_X64_RDI:      *value = regs.rdi; break;
  case VMM_X64_RSP:      *value = regs.rsp; break;
  case VMM_X64_RBP:      *value = regs.rbp; break;
  case VMM_X64_R8:
  case VMM_X64_R9:
  case VMM_X64_R10:
  case VMM_X64_R11:
  case VMM_X64_R12:
  case VMM_X64_R13:
  case VMM_X64_R14:
  case VMM_X64_R15:
  case VMM_X64_CS:
  case VMM_X64_SS:
  case VMM_X64_DS:
  case VMM_X64_ES:
  case VMM_X64_FS:
  case VMM_X64_GS:
  case VMM_X64_IDT_BASE:
  case VMM_X64_IDT_LIMIT:
  case VMM_X64_GDT_BASE:
  case VMM_X64_GDT_LIMIT:
  case VMM_X64_LDTR:
  case VMM_X64_LDT_BASE:
  case VMM_X64_LDT_LIMIT:
  case VMM_X64_LDT_AR:
  case VMM_X64_TR:
  case VMM_X64_TSS_BASE:
  case VMM_X64_TSS_LIMIT:
  case VMM_X64_TSS_AR:
  case VMM_X64_CR0:
  case VMM_X64_CR1:
  case VMM_X64_CR2:
  case VMM_X64_CR3:
  case VMM_X64_CR4:
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
  default:
    assert(false);
  }
  return 0;
}

int
vmm_get(int id, uint64_t *value)
{
  assert(id == VMM_CTRL_EXIT_REASON);

  switch (run->exit_reason) {
  case KVM_EXIT_HLT: *value = VMM_EXIT_HLT; break;
  case KVM_EXIT_IO:  *value = VMM_EXIT_IO; break;
  default:
    *value = VMM_EXIT_REASONS_MAX;
    return -1;
  }
  return 0;
}
