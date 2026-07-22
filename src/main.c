#include "display.h"
#include "elf_parser.h"
#include <stdio.h>

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage %s <path-to-elf-binary>\n", argv[0]);
    return 1;
  }

  const char *filepath = argv[1];
  ElfContext ctx;

  if (elf_init(&ctx, filepath) != 0) {
    fprintf(stderr, "[-] Error: Failed to load file '%s'\n", filepath);
    return 1;
  }

  if (elf_validate(&ctx) == 0) {
    fprintf(stderr, "[-] Error: '%s' is not a valid 64-bit ELF binary.\n",
            filepath);
    elf_cleanup(&ctx);
    return 1;
  }

  display_header_info(&ctx);
  puts("");
  display_mitigations(&ctx);

  elf_cleanup(&ctx);
  return 0;
}
