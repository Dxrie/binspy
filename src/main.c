#include "display.h"
#include "elf_parser.h"
#include "tui.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage %s <path-to-elf-binary>\n", argv[0]);
    return 1;
  }

  const char *filepath = argv[1];
  ElfContext ctx;

  if (elf_init(&ctx, filepath) != 0) {
    fprintf(stderr, "[-] Error: Failed to load file '%s'\n", filepath);
    elf_cleanup(&ctx);
    return 1;
  }

  if (elf_validate(&ctx) == 0) {
    fprintf(stderr, "[-] Error: '%s' is not a valid 64-bit ELF binary.\n",
            filepath);
    elf_cleanup(&ctx);
    return 1;
  }

  tui_run(&ctx, filepath);
  return 0;
}
