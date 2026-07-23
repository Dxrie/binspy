#include "display.h"
#include "elf_parser.h"
#include <capstone/capstone.h>
#include <stdio.h>

#define COLOR_RESET "\033[0m"
#define COLOR_GREEN "\033[1;32m"
#define COLOR_RED "\033[1;31m"
#define COLOR_CYAN "\033[1;36m"
#define COLOR_YELLOW "\033[1;33m"

void display_header_info(const ElfContext *ctx) {
  printf(COLOR_CYAN "=== ELF Header Information ===" COLOR_RESET "\n");
  printf("  %-25s : 0x%lx\n", "Entry point address", ctx->header->e_entry);
  printf("  %-25s : %ld bytes\n", "Start of program headers",
         ctx->header->e_phoff);
  printf("  %-25s : %ld bytes\n", "Start of section headers",
         ctx->header->e_shoff);
  printf("  %-25s : %d\n", "Number of program headers", ctx->header->e_phnum);
  printf("  %-25s : %d\n\n", "Number of section headers", ctx->header->e_shnum);
}

void display_mitigations(const ElfContext *ctx) {
  printf(COLOR_CYAN "=== Binary Protections Information ===" COLOR_RESET "\n");

  int relro_status = is_relro_enabled(ctx);
  printf("  %-15s : ", "RELRO");
  if (relro_status == 0) {
    printf(COLOR_RED "No RELRO" COLOR_RESET "\n");
  } else if (relro_status == 1) {
    printf(COLOR_YELLOW "Partial RELRO" COLOR_RESET "\n");
  } else {
    printf(COLOR_GREEN "Full RELRO" COLOR_RESET "\n");
  }

  printf("  %-15s : ", "PIE");
  if (is_pie_enabled(ctx)) {
    printf(COLOR_GREEN "Enabled" COLOR_RESET "\n");
  } else {
    printf(COLOR_RED "Disabled" COLOR_RESET "\n");
  }

  printf("  %-15s : ", "NX");
  if (is_nx_enabled(ctx)) {
    printf(COLOR_GREEN "Enabled" COLOR_RESET "\n");
  } else {
    printf(COLOR_RED "Disabled" COLOR_RESET "\n");
  }

  printf("  %-15s : ", "Stack Canary");
  if (is_canary_enabled(ctx)) {
    printf(COLOR_GREEN "Enabled" COLOR_RESET "\n");
  } else {
    printf(COLOR_RED "Disabled" COLOR_RESET "\n");
  }

  printf("  %-15s : ", "Symbols");
  if (is_stripped(ctx)) {
    printf(COLOR_RED "No Symbols / Stripped" COLOR_RESET "\n");
  } else {
    printf(COLOR_GREEN "Not Stripped" COLOR_RESET "\n");
  }
  printf("\n");
}

void display_assembly(const ElfFunction *func) {
  csh handle;
  cs_insn *insn;

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
    fprintf(stderr,
            "[-] Error: Failed to initialize Capstone disassembly engine.\n");
    return;
  }

  size_t count =
      cs_disasm(handle, func->code_bytes, func->size, func->vaddr, 0, &insn);

  if (count > 0) {
    printf(COLOR_CYAN "=== Disassembly of %s (Size: %zu bytes) ===" COLOR_RESET
                      "\n",
           func->name, func->size);

    for (size_t i = 0; i < count; i++) {
      printf("  0x%08" PRIx64 ":  %-8s %s\n", insn[i].address, insn[i].mnemonic,
             insn[i].op_str);
    }
    cs_free(insn, count);
  } else {
    printf(COLOR_RED "[-] Failed to disassemble function '%s'\n" COLOR_RESET,
           func->name);
  }

  cs_close(&handle);
}
