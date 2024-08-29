// Copyright (c) 2013, Facebook, Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//   * Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//   * Neither the name Facebook nor the names of its contributors may be used to
//     endorse or promote products derived from this software without specific
//     prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "treblehook.h"
#include <stdio.h>
#include <ptrauth.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <mach/vm_map.h>
#include <mach/vm_region.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <assert.h>
#include <sys/sysctl.h>
#include <os/log.h>
#include <mach-o/ldsyms.h>

#pragma mark - Preprocessor stuff -

#ifdef TARGET_OS_IPHONE // omg, why, Apple
kern_return_t mach_vm_protect
(
  vm_map_t target_task,
  mach_vm_address_t address,
  mach_vm_size_t size,
  boolean_t set_maximum,
  vm_prot_t new_protection
);

kern_return_t mach_vm_write
(
  vm_map_t target_task,
  mach_vm_address_t address,
  vm_offset_t data,
  mach_msg_type_number_t dataCnt
);

kern_return_t mach_vm_deallocate
(
  vm_map_t target,
  mach_vm_address_t address,
  mach_vm_size_t size
);
kern_return_t mach_vm_allocate
(
  vm_map_t target,
  mach_vm_address_t *address,
  mach_vm_size_t size,
  int flags
);
#endif

#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST  "__DATA_CONST"
#endif

#ifdef DEBUG
#define DEBUG_DIAGNOSE() { PRINT_DEBUG("%s:%d trap", __PRETTY_FUNCTION__, __LINE__); __builtin_debugtrap(); }
#else
#define DEBUG_DIAGNOSE()
#endif

#define HANDLE_ERR_RET(X) { kern_return_t ___kr = (X); if (___kr) { PRINT_ERROR( "err: %s\n\t%s:%d %s (%x)\n\n", __FILE__, __PRETTY_FUNCTION__, __LINE__, mach_error_string(___kr), ___kr); DEBUG_DIAGNOSE(); return ___kr;} }
#define HANDLE_ERR(X) { kern_return_t ___kr = (X); if (___kr) { PRINT_ERROR( "err: %s\n\t%s:%d %s (%x)\n\n", __FILE__, __PRETTY_FUNCTION__, __LINE__, mach_error_string(___kr), ___kr); DEBUG_DIAGNOSE();} }
#define PRINT_DEBUG(f_, ...) if (g_print_debug) { os_log(OS_LOG_DEFAULT, f_, ##__VA_ARGS__); }
#define PRINT_ERROR(f_, ...) if (g_print_debug) { os_log_error(OS_LOG_DEFAULT, f_, ##__VA_ARGS__); }

#pragma mark - internal symbols -

// private dyld function
extern intptr_t _dyld_get_image_slide(const struct mach_header* mh);

struct rebindings_entry {
  struct rebinding *rebindings;
  size_t rebindings_nel;
  struct rebindings_entry *next;
};

static bool g_print_debug =
#if DEBUG
                            true;
#else
                            false;
#endif

static struct rebindings_entry *_rebindings_head = NULL;

static void* strip_pac(void* addr) {
#if defined(__arm64__)
  static uint32_t g_addressing_bits = 0;
  
  if (g_addressing_bits == 0) {
    size_t len = sizeof(uint32_t);
    if (sysctlbyname("machdep.virtual_address_size", &g_addressing_bits, &len,
                     NULL, 0) != 0) {
      g_addressing_bits = 0;
    }
  }
  
  uintptr_t mask = ((1UL << g_addressing_bits) - 1) ;
  
  return (void*)((uintptr_t)addr & mask);
#else
  return addr;
#endif
  
}

static int get_mem_protection(void *addr, vm_prot_t *prot, vm_prot_t *max_prot) {
  vm_size_t size = 0;
  vm_address_t address = (vm_address_t)addr;
  memory_object_name_t object = MACH_PORT_NULL;
#ifdef __LP64__
  mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
  vm_region_basic_info_data_64_t info;
  HANDLE_ERR_RET(vm_region_64(mach_task_self(),
                              &address,
                              &size,
                              VM_REGION_BASIC_INFO_64,
                              (vm_region_info_64_t)&info,
                              &count,
                              &object));
#else
  mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT;
  vm_region_basic_info_data_t info;
  kern_return_t info_ret = vm_region(task, &address, &size, VM_REGION_BASIC_INFO, (vm_region_info_t)&info, &count, &object);
#endif
  if (prot != NULL) {
    *prot = info.protection;
  }
    
  if (max_prot != NULL) {
    *max_prot = info.max_protection;
  }
    
  return KERN_SUCCESS;
}

static vm_size_t get_page_size(void) {
  vm_size_t sz = 0;
  host_page_size(HOST_NULL, &sz);
  return sz;
}

#pragma mark - adrp opcode logic -

typedef struct {
  uint32_t reg      :  5; //
  uint32_t val      : 18; //
  uint32_t negative :  1; // If true everything will need to be 2's complement including val2bits
  uint32_t op2      :  5; // must be 0b10000
  uint32_t val2bits :  2; // The lower 2 bits of a value (if any) are stored here
  uint32_t op       :  1; // must be 1
} arm64_adrp_op;
static_assert(sizeof(arm64_adrp_op) == sizeof(uint32_t), "adrp bad size");

bool is_adrp_instruction(uint32_t *insr) {
  arm64_adrp_op *ins =  (void*)insr;
  if (ins->op2 == 0b10000 && ins->op == 1) {
    return true;
  }
  return false;
}

uint32_t create_adrp_opcode(uint8_t reg, uintptr_t start_addr, uintptr_t dest_addr) { // 1
  uint32_t op = 0;
  arm64_adrp_op *a = (void*)&op;
  a->op = 1;
  a->op2 = 0b10000;
  uintptr_t mask = ~((uintptr_t)0xfff);
  int32_t offset = ((int32_t)((dest_addr & mask) - (start_addr & mask))) / 4096;
  a->negative = offset < 0 ? 1 : 0;
  a->reg = reg;
  a->val2bits = (offset & 3);
  // Remaing val contains bit 3 and on, throw away first 2 bits
  a->val = (offset >> 2);
  return op;
}

uintptr_t resolve_adrp_opcode(uint32_t *insr, uint8_t *dreg) {
  arm64_adrp_op *ins =  (void*)insr;
  uintptr_t addr = (uintptr_t)insr & ~0xFFFUL;
  addr += ((ins->val << 2) + (ins->val2bits & 0x3)) * 0x1000;
  if (dreg) {
    *dreg = ins->reg;
  }
  return addr;
}

#pragma mark - ldr opcode logic -

typedef struct {
  uint32_t dreg     :  5; // destination register
  uint32_t sreg     :  5; // source register
  uint32_t val      : 12; // val to be added, val multiples of 8
  uint32_t is_ldr   :  1; // #1 for ldr, 0 for str
  uint32_t op2      :  3; // Should be 0b010
  uint32_t _32_bit  :  1; // 1 if uses 32 bt else 0 for 64
  uint32_t op       :  5; // Should be 0b11111
} arm64_ldr_op;
static_assert(sizeof(arm64_ldr_op) == sizeof(uint32_t), "ldr bad size");

bool is_ldr_instruction(uint32_t *insr) {
  arm64_ldr_op *ins =  (void*)insr;
  if (ins->op == 0b11111 && ins->op2 == 0b010 && ins->is_ldr) {
    return true;
  }
  return false;
}

#pragma mark - add opcode logic -

typedef struct {
  uint32_t dreg     :  5; // destination register
  uint32_t sreg     :  5; // source register
  uint32_t val      : 12; // val to be added, i.e. x4 = x6 + 0x123
  uint32_t lsl      :  1; // #lsl #12 to val
  uint32_t op2      :  7; // Should be 0b0100010
  uint32_t negative :  1; // 1 if negative
  uint32_t op       :  1; // Should be 0b1
} arm64_add_op;
static_assert(sizeof(arm64_add_op) == sizeof(uint32_t), "add bad size");

bool is_add_instruction(uint32_t *insr) {
  arm64_add_op *ins =  (void*)insr;
  if (ins->op == 0b1 && ins->op2 == 0b0100010) {
    return true;
  }
  return false;
}

uint32_t create_add_opcode(uint8_t dreg, uint8_t sreg, int16_t val, bool lslshift) { // 2
  uint32_t op = 0;
  arm64_add_op *a = (void*)&op;
  a->op = 1;
  a->lsl = lslshift;
  a->op2 = 0b0100010;
  a->dreg = dreg;
  a->sreg = sreg;
  a->val = val;
  a->negative = val < 0 ? 1 : 0;
  return op;
}

// NOTE: br NOT blr
#pragma mark - br xN opcode logic -

typedef struct {
  uint32_t unused    :  5; // 0
  uint32_t dreg      :  5; // Which register to branch to
  uint32_t op        : 22; // Should be 0b1101011000011111000000
} arm64_br_op;
static_assert(sizeof(arm64_br_op) == sizeof(uint32_t), "br reg bad size");

typedef struct {
  uint32_t sreg      :  5; // 0
  uint32_t dreg      :  5; // Which register to branch to
  uint32_t op        : 22; // Should be 0b1101011100011111000010
} arm64_braa_op;

static_assert(sizeof(arm64_braa_op) == sizeof(uint32_t), "braa reg bad size");

uint32_t create_br_opcode (uint8_t dreg) {
  uint32_t op = 0;
  arm64_br_op *a = (void*)&op;
  a->op = 0b1101011000011111000000;
  a->dreg = dreg;
  return op;
}

bool is_br_instruction(uint32_t *insr) {
  arm64_br_op *ins =  (void*)insr;
  if (ins->op == 0b1101011000011111000000 ) {
    return true;
  }
  return false;
}

bool is_braa_instruction(uint32_t *insr) {
  arm64_braa_op *ins =  (void*)insr;
  if (ins->op == 0b1101011100011111000010 ) {
    return true;
  }
  return false;
}

static int prepend_rebindings(struct rebindings_entry **rebindings_head,
                              struct rebinding rebindings[],
                              size_t nel) {
  struct rebindings_entry *new_entry = (struct rebindings_entry *) malloc(sizeof(struct rebindings_entry));
  if (!new_entry) {
    return -1;
  }
  new_entry->rebindings = (struct rebinding *) malloc(sizeof(struct rebinding) * nel);
  if (!new_entry->rebindings) {
    free(new_entry);
    return -1;
  }
  memcpy(new_entry->rebindings, rebindings, sizeof(struct rebinding) * nel);
  new_entry->rebindings_nel = nel;
  new_entry->next = *rebindings_head;
  *rebindings_head = new_entry;
  return 0;
}


/// This needs to be free of any explicit function references as this code gets copied to a different page of memory so it doesn't get f'd if we are
/// setting RW- on the calling memory (typically if this code is compiled iinto the same library that is introspecting an external symbol)
static kern_return_t modify_memory(task_t task, vm_address_t address, vm_size_t size, char* patching_address, char* new_value, vm_prot_t og_protection, void* _vm_protect) {
  
  kern_return_t kr = 0;
  
  kern_return_t (*local_vm_protect)(vm_map_t,vm_address_t,vm_size_t,boolean_t,vm_prot_t) = _vm_protect;
  
  kr = local_vm_protect(task, (uintptr_t)address,  size, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
  if (kr == KERN_SUCCESS) {
    /**
     * Once we failed to change the vm protection, we
     * MUST NOT continue the following write actions!
     * iOS 15 has corrected the const segments prot.
     * -- Lionfore Hao Jun 11th, 2021
     **/
    
  }
  for (int i = 0; i < size; i++) {
    patching_address[i] = new_value[i];
  }
  
  kr = local_vm_protect (task, (uintptr_t)address,  size, 0, og_protection);
  return kr;
}

static kern_return_t patch_executable_memory(struct rebindings_entry *cur,  void *indirect_symbol_bindings, void* new_value, vm_size_t patch_size) {
  
  vm_size_t sz = get_page_size();
  mach_vm_address_t addr = 0;
  vm_prot_t protections = 0;
  
  HANDLE_ERR_RET(mach_vm_allocate(mach_task_self(), &addr, sz, VM_FLAGS_ANYWHERE));
  // this should be the default, but make sure...
  HANDLE_ERR_RET(mach_vm_protect(mach_task_self(), addr, sz, 0, VM_PROT_READ|VM_PROT_WRITE));
  // write mem to newly allocated address
  HANDLE_ERR_RET(mach_vm_write(mach_task_self(), addr, (vm_address_t)strip_pac(modify_memory), (mach_msg_type_number_t)sz /* rounding up, yolo */));
  // make it R-X, shouldn't need a COW here
  HANDLE_ERR_RET(vm_protect(mach_task_self(), addr, sz, 0, VM_PROT_READ|VM_PROT_EXECUTE));
  
  vm_address_t patching_memory = (vm_address_t)indirect_symbol_bindings;
  HANDLE_ERR_RET(get_mem_protection((void*)patching_memory, &protections, NULL));
  
  kern_return_t (*dup_modify_memory)(task_t task, vm_address_t address, vm_size_t size, vm_address_t *patching_address, void* new_value, vm_prot_t og_protection, void* _vm_protect) = ptrauth_sign_unauthenticated((void*)addr, ptrauth_key_function_pointer, 0);
  
  HANDLE_ERR_RET(dup_modify_memory(mach_task_self(), patching_memory, patch_size,  (vm_address_t*)indirect_symbol_bindings, new_value, protections, mach_vm_protect));
  
  HANDLE_ERR_RET(mach_vm_deallocate(mach_task_self(), addr, sz));
  
  return KERN_SUCCESS;
}

static void perform_rebinding_with_section(struct rebindings_entry *rebindings,
                                           section_t *section,
                                           intptr_t slide,
                                           nlist_t *symtab,
                                           char *strtab,
                                           uint32_t *indirect_symtab,
                                           uint32_t num_indirect_syms,
                                           bool patch_branch_pool) {
  uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
  void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);
  
  // og code expected pointers, but we need be smart about the size given it's declared in reserved2
  size_t stub_size = section->reserved2;
  for (uint i = 0; i < section->size / (section->reserved2 ? section->reserved2 : sizeof(void*)); i++) {
    uint32_t symtab_index = indirect_symbol_indices[i];
    if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
        symtab_index == (INDIRECT_SYMBOL_LOCAL   | INDIRECT_SYMBOL_ABS)) {
      continue;
    }
    uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
    char *symbol_name = strtab + strtab_offset;
    bool symbol_name_longer_than_1 = symbol_name[0] && symbol_name[1];
    struct rebindings_entry *cur = rebindings;
    while (cur) {
      for (uint j = 0; j < cur->rebindings_nel; j++) {
        if (symbol_name_longer_than_1 && strcmp(&symbol_name[1], cur->rebindings[j].name) == 0) {
          kern_return_t err = KERN_SUCCESS;
          
          if (cur->rebindings[j].replaced != NULL && indirect_symbol_bindings[i] != cur->rebindings[j].replacement) {
            
            
            if (patch_branch_pool) {
              uintptr_t resolved_auth_stub = section->addr + slide + (section->reserved2 * i);
              arm64_adrp_op *adrpop = (void*)resolved_auth_stub;
              union {
                arm64_add_op addop;
                arm64_ldr_op ldrop;
              } *opcode2 = (void*)(resolved_auth_stub + sizeof(uint32_t));
              
              if (!is_adrp_instruction((void*)adrpop)) {
                PRINT_ERROR("Unknown opcode?!!! %x Tell author\n", *(int*)adrpop);
                DEBUG_DIAGNOSE();
                break;
              }
              
              uint8_t destination_reg = 0;
              void** resolved_ptr = (void*)resolve_adrp_opcode((void*)adrpop, &destination_reg);
              if (is_add_instruction((void*)opcode2)) {
                
                if (opcode2->addop.sreg != destination_reg) {
                  PRINT_ERROR("desination adrp reg != add src reg?\n");
                  DEBUG_DIAGNOSE();
                  break;
                }
                resolved_ptr = (void*)(opcode2->addop.val + (uintptr_t)resolved_ptr);
              } else if (is_ldr_instruction((void*)opcode2)) {
                
                if (opcode2->ldrop.sreg != destination_reg) {
                  PRINT_ERROR("desination adrp reg != ldr src reg?\n");
                  DEBUG_DIAGNOSE();
                  break;
                }
                resolved_ptr = (void*)(opcode2->ldrop.val * sizeof(void*) + (uintptr_t)resolved_ptr);
              } else {
                PRINT_ERROR("Unknown opcode?!!! %x Tell author\n", *(int*)opcode2);
                DEBUG_DIAGNOSE();
                break;
              }
              
              
              void* pac_ptr = ptrauth_sign_unauthenticated(strip_pac(*resolved_ptr), ptrauth_key_function_pointer, 0);
              *(cur->rebindings[j].replaced) = pac_ptr;
              
              // It's OK to fail here, __DATA_CONST looks like it's became a pita to un-const
              err = mach_vm_protect(mach_task_self(), (uintptr_t)resolved_ptr, get_page_size(), false, VM_PROT_READ | VM_PROT_WRITE);
              if (err) {
                err = mach_vm_protect(mach_task_self(), (uintptr_t)resolved_ptr, get_page_size(), false, VM_PROT_READ | VM_PROT_WRITE| VM_PROT_COPY);
              }
              if (err == KERN_SUCCESS) {
                /**
                 * Once we failed to change the vm protection, we
                 * MUST NOT continue the following write actions!
                 * iOS 15 has corrected the const segments prot.
                 * -- Lionfore Hao Jun 11th, 2021
                 **/
                *resolved_ptr = ptrauth_sign_unauthenticated(strip_pac(cur->rebindings[j].replacement), ptrauth_key_function_pointer, resolved_ptr);
              } else {
                PRINT_DEBUG("Couldn't modify region %p, trying plan B...\n", resolved_ptr);
                // So this version of macOS they actually made __DATA_CONST a const (wow! 👏)
                // and so I can't change around memory permissions, (unless I did something
                // really dumb and made code from that)...
                //
                // So plan B is to go after the stubs themselves and hope they fall +-4GB away
                // In ARM64e, I have 4 instructions to jump, which will allow all addresses
                // And maybe will be something I impelement one day, but for right now, we'll
                // assume the default of...
                // In arm64, I have 3 instructions which gives me a 4GB+- offset
                // In the future, maybe I'll implement branch pools, but it would take someone
                // who actually reads this to show that someone else is using this code
                // and file a github issue
                //
                // arm64 usually has a reserved size of 0xC
                // which will be something like ardp, add, br
                //
                // arm64e usually has a reserved size of 0x10
                // which will be something like ardp, add, ldr, braa
                // we'll change the braa to a br for arm64e
                
                arm64_br_op *br_opcode = (void *)(uintptr_t)resolved_auth_stub + (sizeof(uint32_t) * 2);
                if (!is_br_instruction((void*)br_opcode) && !is_ldr_instruction((void*)br_opcode)) {
                  PRINT_ERROR("Unknown opcode?!!! 0x%x Tell author\n", *(int*)opcode2);
                  DEBUG_DIAGNOSE();
                }
                
                size_t patch_mem_size = sizeof(uint32_t) * 2;
                uint32_t ops[4] = {};
                
                memcpy(ops, (void*)resolved_auth_stub, sizeof(uint32_t) * 4);
                if (is_ldr_instruction((void*)br_opcode) && is_braa_instruction((void *)(uintptr_t)resolved_auth_stub + (sizeof(uint32_t) * 3))) {
                  br_opcode++;
                  patch_mem_size = sizeof(uint32_t) * 4;
                  uint32_t newopcode = create_br_opcode(destination_reg);
                  ops[2] = 0xD503201F; // no-op
                  memcpy(&ops[3], &newopcode, sizeof(uint32_t));
                  // br has the same jumping reg as braa and we only care about that
                }
                
              

                ops[0] = create_adrp_opcode(destination_reg, resolved_auth_stub, (uintptr_t)strip_pac(cur->rebindings[j].replacement));
                ops[1] = create_add_opcode(destination_reg, destination_reg, (int16_t)(uintptr_t)cur->rebindings[j].replacement & 0xFFF, false);
                HANDLE_ERR(patch_executable_memory(cur, (void*)resolved_auth_stub, (void*)&ops, patch_mem_size));
              }
              
            } else { // !patch_branch_pool
              *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
              
              err = mach_vm_protect (mach_task_self (), (uintptr_t)indirect_symbol_bindings, section->size, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
              if (err == KERN_SUCCESS) {
                /**
                 * Once we failed to change the vm protection, we
                 * MUST NOT continue the following write actions!
                 * iOS 15 has corrected the const segments prot.
                 * -- Lionfore Hao Jun 11th, 2021
                 **/
                indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
              }
            }
          }
          
          goto symbol_loop;
        }
      }
      cur = cur->next;
    }
  symbol_loop:;
  }
}

static void rebind_symbols_for_image(struct rebindings_entry *rebindings,
                                     const struct mach_header *header,
                                     intptr_t slide) {
  segment_command_t *cur_seg_cmd;
  segment_command_t *linkedit_segment = NULL;
  struct symtab_command* symtab_cmd = NULL;
  struct dysymtab_command* dysymtab_cmd = NULL;
  bool patch_branch_pool = false;
  unsigned long sz = 0;
  
  Dl_info info;
  if (dladdr(header, &info) == 0) {
    return;
  }
  if (getsectiondata((void*)header, "__TEXT", "__auth_data", &sz) || getsectiondata((void*)header, "__TEXT", "__auth_stubs", &sz) ) {
    patch_branch_pool = true;
  }
  
  uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
  for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    cur_seg_cmd = (segment_command_t *)cur;
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) {
        linkedit_segment = cur_seg_cmd;
      }
    } else if (cur_seg_cmd->cmd == LC_SYMTAB) {
      symtab_cmd = (struct symtab_command*)cur_seg_cmd;
    } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) {
      dysymtab_cmd = (struct dysymtab_command*)cur_seg_cmd;
    }
  }
  
  if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment ||
      !dysymtab_cmd->nindirectsyms) {
    return;
  }
  
  // Find base symbol/string table addresses
  uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
  nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
  char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
  
  // Get indirect symbol table (array of uint32_t indices into symbol table)
  uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);
  uint32_t num_indirect_syms = dysymtab_cmd->nindirectsyms;
  cur = (uintptr_t)header + sizeof(mach_header_t);
  
  for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    cur_seg_cmd = (segment_command_t *)cur;
    // We'll look for several different paths to hooking depending if it's a dylib in the dsc
    // And if it's arm64[e]
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      if (!strcmp(cur_seg_cmd->segname, SEG_DATA) &&
          !strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) &&
          !strcmp(cur_seg_cmd->segname, SEG_TEXT)) {
        continue;
      }
      
      // __DATA, __DATA_CONST, __TEST segments only from here
      for (uint j = 0; j < cur_seg_cmd->nsects; j++) {
        section_t *sect =
        (section_t *)(cur + sizeof(segment_command_t)) + j;
        if (patch_branch_pool) {
          if ((sect->flags & SECTION_TYPE) == S_SYMBOL_STUBS && strncmp(sect->sectname, "__auth_stubs", 16) == 0) {
            perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab, num_indirect_syms, true);
          }
        } else {
          if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS ||
              (sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
            perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab, num_indirect_syms, false);
          } else if ( (sect->flags & SECTION_TYPE) == S_SYMBOL_STUBS) {
            // Likely a __TEXT.__stubs here
            perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab, num_indirect_syms, true);
          }
        }
      }
    }
  }
}

static void _rebind_symbols_for_image(const struct mach_header *header,
                                      intptr_t slide) {
  rebind_symbols_for_image(_rebindings_head, header, slide);
}

int rebind_symbols_image(void *header,
                         intptr_t slide,
                         struct rebinding rebindings[],
                         size_t rebindings_nel) {
  struct rebindings_entry *rebindings_head = NULL;
  int retval = prepend_rebindings(&rebindings_head, rebindings, rebindings_nel);
  rebind_symbols_for_image(rebindings_head, (const struct mach_header *) header, slide);
  if (rebindings_head) {
    free(rebindings_head->rebindings);
  }
  free(rebindings_head);
  return retval;
}


int rebind_symbols_4_image(void *header,
                           struct rebinding rebindings[],
                           size_t rebindings_nel) {
  intptr_t slide = _dyld_get_image_slide(header);
  struct rebindings_entry *rebindings_head = NULL;
  int retval = prepend_rebindings(&rebindings_head, rebindings, rebindings_nel);
  
  rebind_symbols_for_image(rebindings_head, (const struct mach_header *) header, slide);
  if (rebindings_head) {
    free(rebindings_head->rebindings);
  }
  free(rebindings_head);
  return retval;
}

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel) {
  int retval = prepend_rebindings(&_rebindings_head, rebindings, rebindings_nel);
  if (retval < 0) {
    return retval;
  }
  // If this was the first call, register callback for image additions (which is also invoked for
  // existing images, otherwise, just run on existing images
  if (!_rebindings_head->next) {
    _dyld_register_func_for_add_image(_rebind_symbols_for_image);
  } else {
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++) {
      _rebind_symbols_for_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
    }
  }
  return retval;
}
