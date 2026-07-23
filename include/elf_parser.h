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

/* helper structure for functions inside the binary */
typedef struct {
  const uint8_t *code_bytes; /* pointer to machine code bytes in map_data */
  uint64_t vaddr;            /* virtual memory address */
  size_t size;               /* size of the function (bytes) */
  const char *name;          /* function name */
} ElfFunction;

/* helper structure for function list */
typedef struct {
  ElfFunction *functions;
  size_t count;
} ElfFunctionList;

/* core functions */
int elf_init(ElfContext *ctx, const char *filepath);
void elf_cleanup(ElfContext *ctx);
int elf_validate(const ElfContext *ctx);

/* validate functions */
int is_pie_enabled(const ElfContext *ctx);
int is_nx_enabled(const ElfContext *ctx);
int is_canary_enabled(const ElfContext *ctx);
int is_stripped(const ElfContext *ctx);
int is_relro_enabled(const ElfContext *ctx); /* 0: disabled, 1: partial, 2:
                                                enabled (full RELRO) */

/* disassembler helper functions */
int elf_find_function(const ElfContext *ctx, const char *function_name,
                      ElfFunction *func);
int elf_find_all_functions(const ElfContext *ctx,
                           ElfFunctionList *functionList);
void elf_free_function_list(ElfFunctionList *functionList);

#endif
