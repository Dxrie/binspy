#ifndef DISPLAY_H
#define DISPLAY_H

#include "elf_parser.h"

/* terminal display functions */
void display_header_info(const ElfContext *ctx);
void display_mitigations(const ElfContext *ctx);
void display_assembly(const ElfFunction *func);

#endif
