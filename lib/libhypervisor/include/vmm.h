#ifndef VMM_H
#define VMM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <errno.h>

#define VMM_EBUSY   (-EBUSY)
#define VMM_EINVAL  (-EINVAL)
#define VMM_ENOMEM  (-ENOMEM)
#define VMM_ENODEV  (-ENODEV)
#define VMM_ENOTSUP (-ENOTSUP)

typedef enum {
  VMM_X64_RIP,
  VMM_X64_RFLAGS,
  VMM_X64_RAX,
  VMM_X64_RCX,
  VMM_X64_RDX,
  VMM_X64_RBX,
  VMM_X64_RSI,
  VMM_X64_RDI,
  VMM_X64_RSP,
  VMM_X64_RBP,
  VMM_X64_R8,
  VMM_X64_R9,
  VMM_X64_R10,
  VMM_X64_R11,
  VMM_X64_R12,
  VMM_X64_R13,
  VMM_X64_R14,
  VMM_X64_R15,
  VMM_X64_CS,
  VMM_X64_CS_BASE,
  VMM_X64_CS_LIMIT,
  VMM_X64_CS_AR,
  VMM_X64_SS,
  VMM_X64_SS_BASE,
  VMM_X64_SS_LIMIT,
  VMM_X64_SS_AR,
  VMM_X64_DS,
  VMM_X64_DS_BASE,
  VMM_X64_DS_LIMIT,
  VMM_X64_DS_AR,
  VMM_X64_ES,
  VMM_X64_ES_BASE,
  VMM_X64_ES_LIMIT,
  VMM_X64_ES_AR,
  VMM_X64_FS,
  VMM_X64_FS_BASE,
  VMM_X64_FS_LIMIT,
  VMM_X64_FS_AR,
  VMM_X64_GS,
  VMM_X64_GS_BASE,
  VMM_X64_GS_LIMIT,
  VMM_X64_GS_AR,
  VMM_X64_IDT_BASE,
  VMM_X64_IDT_LIMIT,
  VMM_X64_GDT_BASE,
  VMM_X64_GDT_LIMIT,
  VMM_X64_LDTR,
  VMM_X64_LDT_BASE,
  VMM_X64_LDT_LIMIT,
  VMM_X64_LDT_AR,
  VMM_X64_TR,
  VMM_X64_TSS_BASE,
  VMM_X64_TSS_LIMIT,
  VMM_X64_TSS_AR,
  VMM_X64_CR0,
  VMM_X64_CR1,
  VMM_X64_CR2,
  VMM_X64_CR3,
  VMM_X64_CR4,
  VMM_X64_DR0,
  VMM_X64_DR1,
  VMM_X64_DR2,
  VMM_X64_DR3,
  VMM_X64_DR4,
  VMM_X64_DR5,
  VMM_X64_DR6,
  VMM_X64_DR7,
  VMM_X64_TPR,
  VMM_X64_XCR0,
  VMM_X64_REGISTERS_MAX,
} vmm_x64_reg_t;

enum {
  VMM_CTRL_EXIT_REASON,
};

enum {
  VMM_EXIT_HLT,
  VMM_EXIT_IO,
  VMM_EXIT_REASONS_MAX,
};

typedef struct vmm_vm *vmm_vm_t;

int vmm_create(vmm_vm_t *vm);
int vmm_destroy(vmm_vm_t vm);

typedef struct vmm_cpu *vmm_cpu_t;

int vmm_cpu_create(vmm_vm_t vm, vmm_cpu_t *cpu);
int vmm_cpu_destroy(vmm_vm_t vm, vmm_cpu_t cpu);
int vmm_cpu_run(vmm_vm_t vm, vmm_cpu_t cpu);
int vmm_cpu_get_register(vmm_vm_t vm, vmm_cpu_t cpu, vmm_x64_reg_t reg, uint64_t *value);
int vmm_cpu_set_register(vmm_vm_t vm, vmm_cpu_t cpu, vmm_x64_reg_t reg, uint64_t value);
int vmm_cpu_get_msr(vmm_vm_t vm, vmm_cpu_t cpu, uint32_t msr, uint64_t *value);
int vmm_cpu_set_msr(vmm_vm_t vm, vmm_cpu_t cpu, uint32_t msr, uint64_t value);
int vmm_cpu_get_state(vmm_vm_t vm, vmm_cpu_t cpu, int id, uint64_t *value);
int vmm_cpu_set_state(vmm_vm_t vm, vmm_cpu_t cpu, int id, uint64_t value);

typedef const void *vmm_uvaddr_t;
typedef uint64_t vmm_gpaddr_t;

int vmm_memory_map(vmm_vm_t vm, vmm_uvaddr_t uva, vmm_gpaddr_t gpa, size_t size, int prot);
int vmm_memory_unmap(vmm_vm_t vm, vmm_gpaddr_t gpa, size_t size);
int vmm_memory_protect(vmm_vm_t vm, vmm_gpaddr_t gpa, size_t size, int prot);

#ifdef __cplusplus
}
#endif

#endif
