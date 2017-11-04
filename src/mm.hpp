#ifndef ISOLATION_MM_H
#define ISOLATION_MM_H

#include "types.hpp"

#define __page_aligned __attribute__((aligned(0x1000)))

static const int PAGE_4KB = 4096;
static const int PAGE_ALIGN_MASK = (PAGE_4KB - 1);


static const uint64_t PTE_P =  0x001;   // Present
static const uint64_t PTE_W =  0x002;   // Writeable
static const uint64_t PTE_U =  0x004;   // User
static const uint64_t PTE_PS = 0x080;   // Page Size
static const uint64_t PTE_NX = 0x8000000000000000; // No Execute

static const gaddr_t user_addr_max = 0x0000007fc0000000ULL;

static const int NR_PAGE_ENTRY = 512;

gaddr_t kmap(vmm_vm_t vm, void *ptr, size_t size, int flags);
void init_page(vmm_vm_t vm, vmm_cpu_t cpu);
void init_segment(vmm_vm_t vm, vmm_cpu_t cpu);

#endif
