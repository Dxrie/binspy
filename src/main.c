#include "display.h"
#include "elf_parser.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage %s <path-to-elf-binary>\n", argv[0]);
    return 1;
  }

  const char *cmd = argv[1];

  if (strcmp(cmd, "security") == 0 || strcmp(cmd, "sec") == 0 ||
      strcmp(cmd, "checksec") == 0 || strcmp(cmd, "checksecurity") == 0) {
    if (argc < 3) {
      fprintf(stderr, "Usage %s security <path-to-elf-binary>\n", argv[0]);
      return 1;
    }

    const char *filepath = argv[2];
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

    puts("");
    display_header_info(&ctx);
    puts("");
    display_mitigations(&ctx);

    elf_cleanup(&ctx);
  }

  if (strcmp(cmd, "disass") == 0 || strcmp(cmd, "disassemble") == 0) {
    if (argc < 4) {
      fprintf(stderr, "Usage %s disass <path-to-elf-binary> <function-name>\n",
              argv[0]);
      return 1;
    }

    const char *filepath = argv[2];
    const char *function_name = argv[3];
    ElfContext ctx;
    ElfFunction func;

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

    if (elf_find_function(&ctx, function_name, &func) == 0) {
      fprintf(stderr,
              "[-] Error: No function with the name \"%s\" was found.\n",
              function_name);
      elf_cleanup(&ctx);
      return 1;
    }

    puts("");
    display_assembly(&func);
    puts("");
  }

  return 0;
}
