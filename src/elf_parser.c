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
