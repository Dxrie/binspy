#include "display.h"
#include "elf_parser.h"
#include <stdio.h>

#define COLOR_RESET "\033[0m"
#define COLOR_GREEN "\033[1;32m"
#define COLOR_RED "\033[1;31m"
#define COLOR_CYAN "\033[1;36m"
#define COLOR_YELLOW "\033[33m"

void display_header_info(const ElfContext *ctx) {
  printf(COLOR_CYAN "=== ELF Header Information ===" COLOR_RESET "\n");
  printf("Entry point address: 0x%lx\n", ctx->header->e_entry);
  printf("Start of program headers: %ld (bytes into file)\n",
         ctx->header->e_phoff);
  printf("Start of section headers: %ld (bytes into file)\n",
         ctx->header->e_shoff);
  printf("Number of program headers: %d\n", ctx->header->e_phnum);
  printf("Number of section headers: %d\n", ctx->header->e_shnum);
}

void display_mitigations(const ElfContext *ctx) {
  printf(COLOR_CYAN "=== Binary Protections Information ===" COLOR_RESET "\n");

  int relro_status = is_relro_enabled(ctx);

  if (relro_status == 0) {
    printf(COLOR_RED "[-] RELRO: Disabled" COLOR_RESET "\n");
  } else if (relro_status == 1) {
    printf(COLOR_YELLOW "[+] RELRO: Partial RELRO" COLOR_RESET "\n");
  } else {
    printf(COLOR_GREEN "[+] RELRO: Full RELRO" COLOR_RESET "\n");
  }

  if (is_pie_enabled(ctx)) {
    printf(COLOR_GREEN
           "[+] PIE (Position Independent Executable): Enabled" COLOR_RESET
           "\n");
  } else {
    printf(COLOR_RED "[-] PIE (Position Independent Executable): "
                     "Disabled" COLOR_RESET "\n");
  }

  if (is_nx_enabled(ctx)) {
    printf(COLOR_GREEN "[+] NX: Enabled" COLOR_RESET "\n");
  } else {
    printf(COLOR_RED "[-] NX: Disabled" COLOR_RESET "\n");
  }

  if (is_canary_enabled(ctx)) {
    printf(COLOR_GREEN "[+] Stack Canary: Enabled" COLOR_RESET "\n");
  } else {
    printf(COLOR_RED "[-] Stack Canary: Disabled" COLOR_RESET "\n");
  }

  if (is_stripped(ctx)) {
    printf(COLOR_RED "[-] Symbols: Stripped" COLOR_RESET "\n");
  } else {
    printf(COLOR_GREEN "[+] Symbols: Not Stripped" COLOR_RESET "\n");
  }
}
