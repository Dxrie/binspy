#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <elf.h>
#include <stddef.h>
#include <stdint.h>

/* helper structure to track mapped binary state */
typedef struct {
  void *map_data;     /* pointer returned by mmap */
  size_t file_size;   /* total size of the mapped file */
  Elf64_Ehdr *header; /* pointer to the ELF header */
} ElfContext;

/* core functions */
int elf_init(ElfContext *ctx, const char *filepath);
void elf_cleanup(ElfContext *ctx);

/* inspection functions */
int elf_validate(const ElfContext *ctx);
void elf_check_mitigations(const ElfContext *ctx);

#endif
