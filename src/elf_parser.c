#include "elf_parser.h"
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int elf_init(ElfContext *ctx, const char *filepath) {
  if (!ctx || !filepath)
    return -1;
  memset(ctx, 0, sizeof(ElfContext));

  int fd = open(filepath, O_RDONLY);

  struct stat st;
  if (fstat(fd, &st) < 0) {
    perror("fstat");
    close(fd);
    return -1;
  }
  ctx->file_size = st.st_size;
  ctx->map_data = mmap(NULL, ctx->file_size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);

  if (ctx->map_data == MAP_FAILED) {
    perror("mmap");
    ctx->map_data = NULL;
    return -1;
  }

  ctx->header = (Elf64_Ehdr *)ctx->map_data;
  return 0;
}

int elf_validate(const ElfContext *ctx) {
  if (!ctx || !ctx->map_data || ctx->file_size < sizeof(Elf64_Ehdr)) {
    return 0; // invalid context or file too small
  }

  if (ctx->header->e_ident[0] != ELFMAG0 ||
      ctx->header->e_ident[1] != ELFMAG1 ||
      ctx->header->e_ident[2] != ELFMAG2 ||
      ctx->header->e_ident[3] != ELFMAG3 ||
      ctx->header->e_ident[EI_CLASS] != ELFCLASS64) {
    // invalid ELF file or not 64 bit (prob gonna implement 32 bit later on)
    return 0;
  }

  return 1; // valid ELF file
}

void elf_cleanup(ElfContext *ctx) {
  if (ctx && ctx->map_data) {
    munmap(ctx->map_data, ctx->file_size);
    ctx->map_data = NULL;
    ctx->file_size = 0;
    ctx->header = NULL;
  }
}

int is_pie_enabled(const ElfContext *ctx) {
  return ctx->header->e_type == ET_DYN;
}

int is_nx_enabled(const ElfContext *ctx) {
  Elf64_Phdr *ph_table =
      (Elf64_Phdr *)((uint8_t *)ctx->map_data + ctx->header->e_phoff);

  int nx_enabled = 1;

  for (int i = 0; i < ctx->header->e_phnum; i++) {
    if (ph_table[i].p_type == PT_GNU_STACK) {
      if (ph_table[i].p_flags & PF_X) {
        nx_enabled = 0;
      }
      break;
    }
  }

  return nx_enabled;
}

int is_canary_enabled(const ElfContext *ctx) {
  Elf64_Shdr *sh_table =
      (Elf64_Shdr *)((uint8_t *)ctx->map_data + ctx->header->e_shoff);

  Elf64_Shdr *dynsym_shdr = NULL;
  Elf64_Shdr *dynstr_shdr = NULL;

  for (int i = 0; i < ctx->header->e_shnum; i++) {
    if (sh_table[i].sh_type == SHT_DYNSYM) {
      dynsym_shdr = &sh_table[i];
      if (dynsym_shdr->sh_link < ctx->header->e_shnum) {
        dynstr_shdr = &sh_table[dynsym_shdr->sh_link];
      }
      break;
    }
  }

  if (!dynsym_shdr || !dynstr_shdr) {
    return 0;
  }

  Elf64_Sym *sym_table =
      (Elf64_Sym *)((uint8_t *)ctx->map_data + dynsym_shdr->sh_offset);
  const char *str_table =
      (const char *)((uint8_t *)ctx->map_data + dynstr_shdr->sh_offset);

  size_t num_symbols = dynsym_shdr->sh_size / sizeof(Elf64_Sym);

  // iterate through symbols to look for "__stack_chk_fail"
  for (size_t i = 0; i < num_symbols; i++) {
    if (sym_table[i].st_name < dynstr_shdr->sh_size) {
      const char *sym_name = str_table + sym_table[i].st_name;
      if (strcmp(sym_name, "__stack_chk_fail") == 0) {
        return 1; // canary enabled
      }
    }
  }

  return 0; // canary disabled
}

int is_stripped(const ElfContext *ctx) {
  Elf64_Shdr *sh_table =
      (Elf64_Shdr *)((uint8_t *)ctx->map_data + ctx->header->e_shoff);

  for (int i = 0; i < ctx->header->e_shnum; i++) {
    if (sh_table[i].sh_type == SHT_SYMTAB && sh_table[i].sh_size > 0) {
      return 0;
    }
  }

  return 1;
}

int is_relro_enabled(const ElfContext *ctx) {
  int has_relro_segment = 0;
  Elf64_Phdr *ph_table =
      (Elf64_Phdr *)((uint8_t *)ctx->map_data + ctx->header->e_phoff);

  for (int i = 0; i < ctx->header->e_phnum; i++) {
    if (ph_table[i].p_type == PT_GNU_RELRO) {
      has_relro_segment = 1;
      break;
    }
  }

  int bind_now = 0;
  Elf64_Shdr *sh_table =
      (Elf64_Shdr *)((uint8_t *)ctx->map_data + ctx->header->e_shoff);

  for (int i = 0; i < ctx->header->e_shnum; i++) {
    if (sh_table[i].sh_type == SHT_DYNAMIC) {
      Elf64_Dyn *dyn_table =
          (Elf64_Dyn *)((uint8_t *)ctx->map_data + sh_table[i].sh_offset);
      size_t num_dyn = sh_table[i].sh_size / sizeof(Elf64_Dyn);

      for (size_t j = 0; j < num_dyn; j++) {
        if (dyn_table[j].d_tag == DT_NULL) {
          break; // DT_NULL marks the end of dynamic section
        }
        if (dyn_table[j].d_tag == DT_BIND_NOW) {
          bind_now = 1;
        } else if (dyn_table[j].d_tag == DT_FLAGS &&
                   (dyn_table[j].d_un.d_val & DF_BIND_NOW)) {
          bind_now = 1;
        } else if (dyn_table[j].d_tag == DT_FLAGS_1 &&
                   (dyn_table[j].d_un.d_val & DF_1_NOW)) {
          bind_now = 1;
        }
      }
      break;
    }
  }

  if (!has_relro_segment) {
    return 0;
  }

  if (bind_now) {
    return 2;
  }

  return 1;
}
