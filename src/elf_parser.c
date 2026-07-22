#include "elf_parser.h"
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static void elf_pie_check(const ElfContext *ctx);
static void elf_nx_check(const ElfContext *ctx);

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
      ctx->header->e_ident[EI_CLASS] == ELFCLASS64) {
    // invalid ELF file or not 64 bit (prob gonna implement 32 bit later on)
    return 0;
  }

  return 1; // valid ELF file
}

void elf_print_header_info(const ElfContext *ctx) {
  if (!elf_validate(ctx)) {
    printf("\033[1;31m[-] Invalid 64 bit ELF binary.\033[0m\n");
    return;
  }

  printf("=== ELF Header ===\n");
  printf("Entry point address: 0x%lx\n", ctx->header->e_entry);
  printf("Start of program headers: %ld (bytes into file)\n",
         ctx->header->e_phoff);
  printf("Start of section headers: %ld (bytes into file)\n",
         ctx->header->e_shoff);
  printf("Number of program headers: %d\n", ctx->header->e_phnum);
  printf("Number of section headers: %d\n", ctx->header->e_shnum);
}

void elf_cleanup(ElfContext *ctx) {
  if (ctx && ctx->map_data) {
    munmap(ctx->map_data, ctx->file_size);
    ctx->map_data = NULL;
    ctx->file_size = 0;
    ctx->header = NULL;
  }
}

void elf_check_mitigations(const ElfContext *ctx) {
  int is_pie_enabled = 0;

  if (!elf_validate(ctx)) {
    printf("\033[1;31m[-] Invalid 64 bit ELF binary.\033[0m\n");
    return;
  }

  elf_pie_check(ctx);
  elf_nx_check(ctx);
}

static void elf_pie_check(const ElfContext *ctx) {
  if (ctx->header->e_type == ET_DYN) {
    printf(
        "\033[32m[+] PIE (Position Independent Executable): Enabled\033[0m\n");
  } else {
    printf("\033[1;31m[-] PIE (Position Independent Executable): "
           "Disabled\033[0m\n");
  }
}

static void elf_nx_check(const ElfContext *ctx) {
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

  if (nx_enabled) {
    printf("\033[32m[+] NX: Enabled\033[0m\n");
  } else {
    printf("\033[1;31m[-] NX: Disabled\033[0m\n");
  }
}
