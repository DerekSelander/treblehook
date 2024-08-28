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

struct rebindings_entry {
  struct rebinding *rebindings;
  size_t rebindings_nel;
  struct rebindings_entry *next;
};

// private dyld function
extern intptr_t _dyld_get_image_slide(const struct mach_header* mh);

static struct rebindings_entry *_rebindings_head;

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

#if 0
static int get_protection(void *addr, vm_prot_t *prot, vm_prot_t *max_prot) {
  mach_port_t task = mach_task_self();
  vm_size_t size = 0;
  vm_address_t address = (vm_address_t)addr;
  memory_object_name_t object;
#ifdef __LP64__
  mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
  vm_region_basic_info_data_64_t info;
  kern_return_t info_ret = vm_region_64(
                                        task, &address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_64_t)&info, &count, &object);
#else
  mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT;
  vm_region_basic_info_data_t info;
  kern_return_t info_ret = vm_region(task, &address, &size, VM_REGION_BASIC_INFO, (vm_region_info_t)&info, &count, &object);
#endif
  if (info_ret == KERN_SUCCESS) {
    if (prot != NULL)
      *prot = info.protection;
    
    if (max_prot != NULL)
      *max_prot = info.max_protection;
    
    return 0;
  }
  
  return -1;
}
#endif

typedef struct {
  uint32_t reg      :  5; //
  uint32_t val      : 18; //
  uint32_t negative :  1; // If true everything will need to be 2's complement including val2bits
  uint32_t op2      :  5; // must be 0b10000
  uint32_t val2bits :  2; // The lower 2 bits of a value (if any) are stored here
  uint32_t op       :  1; // must be 1
} arm64_adrp_op;

typedef struct {
  uint32_t unused    :  5; // 0
  uint32_t dreg      :  5; // Which register to branch to
  uint32_t op        : 22; // Should be 0b1101011000011111000000
} arm64_brreg_op;

typedef struct {
  uint32_t dreg     :  5; // destination register
  uint32_t sreg     :  5; // source register
  uint32_t val      : 12; // val to be added, i.e. x4 = x6 + 0x123
  uint32_t lsl      :  1; // #lsl #12 to val
  uint32_t op2      :  7; // Should be 0b01000100
  uint32_t negative :  1; // 1 if negative
  uint32_t op       :  1; // Should be 0b1
} arm64_add_op;

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
          kern_return_t err;
          
          if (cur->rebindings[j].replaced != NULL && indirect_symbol_bindings[i] != cur->rebindings[j].replacement) {
            
            if (patch_branch_pool) {
              uintptr_t resolved_auth_stub = section->addr + slide + (section->reserved2 * i);
              arm64_adrp_op *adrpop = (void*)resolved_auth_stub;
              arm64_add_op *addop = (void*)(resolved_auth_stub + sizeof(uint32_t));
              
              intptr_t pageOffset = ((adrpop->val << 2) + adrpop->val2bits) * (adrpop->negative ? -1 : 1);
              uint32_t offset = (addop->negative ? -addop->val : addop->val);
              offset = addop->lsl ? offset << 12 : offset;
              void **resolved_ptr = (void*)(((resolved_auth_stub & ~0xfffUL) + (pageOffset * 0x1000)) + offset);
              
              void* pac_ptr = ptrauth_sign_unauthenticated(strip_pac(*resolved_ptr), ptrauth_key_function_pointer, 0);
              *(cur->rebindings[j].replaced) = pac_ptr;
              err = vm_protect (mach_task_self (), (uintptr_t)resolved_ptr, 0x1000, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
              if (err == KERN_SUCCESS) {
                /**
                 * Once we failed to change the vm protection, we
                 * MUST NOT continue the following write actions!
                 * iOS 15 has corrected the const segments prot.
                 * -- Lionfore Hao Jun 11th, 2021
                 **/
                *resolved_ptr = ptrauth_sign_unauthenticated(strip_pac(cur->rebindings[j].replacement), ptrauth_key_function_pointer, resolved_ptr);
              }
            } else {
              *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
              err = vm_protect (mach_task_self (), (uintptr_t)indirect_symbol_bindings, section->size, 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
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
  Dl_info info;
  if (dladdr(header, &info) == 0) {
    return;
  }
  bool patch_branch_pool = false;
  unsigned long sz = 0;
  if (getsectiondata((void*)header, "__TEXT", "__auth_data", &sz)) {
    patch_branch_pool = true;
  }
  
  segment_command_t *cur_seg_cmd;
  segment_command_t *linkedit_segment = NULL;
  struct symtab_command* symtab_cmd = NULL;
  struct dysymtab_command* dysymtab_cmd = NULL;
  
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
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
          strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) != 0 &&
          strcmp(cur_seg_cmd->segname, SEG_TEXT) != 0) {
        continue;
      }
      for (uint j = 0; j < cur_seg_cmd->nsects; j++) {
        section_t *sect =
        (section_t *)(cur + sizeof(segment_command_t)) + j;
        if (patch_branch_pool) {
          if ((sect->flags & SECTION_TYPE) == S_SYMBOL_STUBS && strncmp(sect->sectname, "__auth_stubs", 16) == 0) {
            perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab, num_indirect_syms, true);
          }
        } else {
          if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) {
            perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab, num_indirect_syms, false);
          }
          if ((sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
            perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab, num_indirect_syms, false);
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
