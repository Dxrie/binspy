#include "tui.h"
#include "elf_parser.h"
#include <capstone/capstone.h>
#include <inttypes.h>
#include <ncurses.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define COLOR_PAIR_HEADER 1
#define COLOR_PAIR_STATUS 2
#define COLOR_PAIR_SELECTED 3
#define COLOR_PAIR_MNEMONIC 4
#define COLOR_PAIR_ADDR 5
#define COLOR_PAIR_GOOD 6
#define COLOR_PAIR_BAD 7
#define COLOR_PAIR_MID 8
#define COLOR_PAIR_FOCUS 9
#define COLOR_PAIR_REG 10
#define COLOR_PAIR_IMM 11
#define COLOR_PAIR_FUNC 12

typedef enum { FOCUS_SIDEBAR = 0, FOCUS_DISASM = 1 } TuiFocus;

static void init_ncurses_colors(void) {
  if (has_colors()) {
    start_color();
    use_default_colors();

    init_pair(COLOR_PAIR_HEADER, COLOR_CYAN, -1);
    init_pair(COLOR_PAIR_STATUS, COLOR_BLACK, COLOR_CYAN);
    init_pair(COLOR_PAIR_SELECTED, COLOR_BLACK, COLOR_GREEN);
    init_pair(COLOR_PAIR_ADDR, COLOR_MAGENTA, -1);
    init_pair(COLOR_PAIR_MNEMONIC, COLOR_RED, -1);
    init_pair(COLOR_PAIR_GOOD, COLOR_GREEN, COLOR_CYAN);
    init_pair(COLOR_PAIR_BAD, COLOR_RED, COLOR_CYAN);
    init_pair(COLOR_PAIR_FOCUS, COLOR_CYAN, -1);
    init_pair(COLOR_PAIR_REG, COLOR_YELLOW, -1);
    init_pair(COLOR_PAIR_IMM, COLOR_GREEN, -1);
    init_pair(COLOR_PAIR_MID, COLOR_YELLOW, COLOR_CYAN);
    init_pair(COLOR_PAIR_FUNC, COLOR_MAGENTA, -1);
  }
}

static void draw_sidebar(WINDOW *sidebar_win,
                         const ElfFunctionList *functionList,
                         size_t selectedIdx, size_t scrollOffset,
                         int isFocused) {
  werase(sidebar_win);

  // Draw colored border if focused
  if (isFocused) {
    wattron(sidebar_win, COLOR_PAIR(COLOR_PAIR_FOCUS));
    box(sidebar_win, 0, 0);
    mvwprintw(sidebar_win, 0, 2, "[ Functions (%zu) ]",
              functionList ? functionList->count : 0);
    wattroff(sidebar_win, COLOR_PAIR(COLOR_PAIR_FOCUS));
  } else {
    box(sidebar_win, 0, 0);
    wattron(sidebar_win, COLOR_PAIR(COLOR_PAIR_HEADER));
    mvwprintw(sidebar_win, 0, 2, "[ Functions (%zu) ]",
              functionList ? functionList->count : 0);
    wattroff(sidebar_win, COLOR_PAIR(COLOR_PAIR_HEADER));
  }

  if (!functionList || functionList->count == 0) {
    mvwprintw(sidebar_win, 2, 2, "No symbols found");
    wnoutrefresh(sidebar_win);
    return;
  }

  int height, width;
  getmaxyx(sidebar_win, height, width);
  int printable_rows = height - 2;

  for (int i = 0; i < printable_rows; i++) {
    size_t idx = scrollOffset + i;
    if (idx >= functionList->count)
      break;

    int row = i + 1;
    if (idx == selectedIdx) {
      wattron(sidebar_win, COLOR_PAIR(COLOR_PAIR_SELECTED));
      mvwprintw(sidebar_win, row, 1, "> %-.*s", width - 4,
                functionList->functions[idx].name);
      wattroff(sidebar_win, COLOR_PAIR(COLOR_PAIR_SELECTED));
    } else {
      mvwprintw(sidebar_win, row, 1, "  %-.*s", width - 4,
                functionList->functions[idx].name);
    }
  }

  wnoutrefresh(sidebar_win);
}

static size_t get_instruction_count(const ElfFunction *selectedFunction) {
  if (!selectedFunction || selectedFunction->size == 0 ||
      !selectedFunction->code_bytes)
    return 0;

  csh handle;
  cs_insn *insn;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    return 0;

  size_t count =
      cs_disasm(handle, selectedFunction->code_bytes, selectedFunction->size,
                selectedFunction->vaddr, 0, &insn);

  if (count > 0)
    cs_free(insn, count);

  cs_close(&handle);
  return count;
}

// 100% vibe coded this shi
static void draw_operands(WINDOW *win, int row, int col, const char *mnemonic,
                          const char *op_str, int max_width,
                          const ElfFunctionList *functionList) {
  int currentCol = col;
  const char *p = op_str;

  while (*p && (currentCol - col) < max_width) {
    if (*p == ' ') {
      mvwaddch(win, row, currentCol++, *p++);
      continue;
    }

    if (strchr("[],+-:*", *p)) {
      mvwaddch(win, row, currentCol++, *p++);
      continue;
    }

    if (*p >= '0' && *p <= '9') {
      char imm_buf[64];
      int imm_i = 0;
      wattron(win, COLOR_PAIR(COLOR_PAIR_IMM));
      while (*p && ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') ||
                    (*p >= 'A' && *p <= 'F') || *p == 'x' || *p == 'X')) {
        if (imm_i < 63)
          imm_buf[imm_i++] = *p;
        if ((currentCol - col) >= max_width) {
          p++;
          continue;
        }
        mvwaddch(win, row, currentCol++, *p++);
      }
      imm_buf[imm_i] = '\0';
      wattroff(win, COLOR_PAIR(COLOR_PAIR_IMM));

      if (mnemonic &&
          (strncmp(mnemonic, "call", 4) == 0 || mnemonic[0] == 'j')) {
        uint64_t target_addr = strtoull(imm_buf, NULL, 16);
        if (target_addr != 0 && functionList) {
          for (size_t f = 0; f < functionList->count; f++) {
            if (functionList->functions[f].vaddr == target_addr) {
              const char *fname = functionList->functions[f].name;
              int f_len = strlen(fname);
              if (currentCol - col + f_len + 3 < max_width) {
                mvwaddch(win, row, currentCol++, ' ');
                mvwaddch(win, row, currentCol++, '<');
                wattron(win, COLOR_PAIR(COLOR_PAIR_FUNC));
                for (int j = 0; j < f_len; j++) {
                  mvwaddch(win, row, currentCol++, fname[j]);
                }
                wattroff(win, COLOR_PAIR(COLOR_PAIR_FUNC));
                mvwaddch(win, row, currentCol++, '>');
              }
              break;
            }
          }
        }
      }
      continue;
    }

    if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z')) {
      char buf[64];
      int i = 0;
      while (*p &&
             ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9')) &&
             i < 63) {
        buf[i++] = *p++;
      }
      buf[i] = '\0';

      int isKeyword = 0;
      const char *keywords[] = {"ptr",     "byte",    "word",
                                "dword",   "qword",   "xmmword",
                                "ymmword", "zmmword", NULL};
      for (int k = 0; keywords[k]; k++) {
        if (strcasecmp(buf, keywords[k]) == 0) {
          isKeyword = 1;
          break;
        }
      }

      if (isKeyword) {
        for (int j = 0; j < i && (currentCol - col) < max_width; j++) {
          mvwaddch(win, row, currentCol++, buf[j]);
        }
      } else {
        wattron(win, COLOR_PAIR(COLOR_PAIR_REG));
        for (int j = 0; j < i && (currentCol - col) < max_width; j++) {
          mvwaddch(win, row, currentCol++, buf[j]);
        }
        wattroff(win, COLOR_PAIR(COLOR_PAIR_REG));
      }
      continue;
    }

    mvwaddch(win, row, currentCol++, *p++);
  }
}

static void draw_main(WINDOW *main_win, const ElfFunction *selectedFunction,
                      size_t disasmScroll, int isFocused,
                      const ElfFunctionList *functionList) {
  werase(main_win);

  if (isFocused) {
    wattron(main_win, COLOR_PAIR(COLOR_PAIR_FOCUS));
    box(main_win, 0, 0);
    mvwprintw(main_win, 0, 2, "[ Disassembly: %s ]",
              selectedFunction ? selectedFunction->name : "None");
    wattroff(main_win, COLOR_PAIR(COLOR_PAIR_FOCUS));
  } else {
    box(main_win, 0, 0);
    wattron(main_win, COLOR_PAIR(COLOR_PAIR_HEADER));
    mvwprintw(main_win, 0, 2, "[ Disassembly: %s ]",
              selectedFunction ? selectedFunction->name : "None");
    wattroff(main_win, COLOR_PAIR(COLOR_PAIR_HEADER));
  }

  if (!selectedFunction || selectedFunction->size == 0 ||
      !selectedFunction->code_bytes) {
    mvwprintw(main_win, 2, 2, "Select a valid function to disassemble");
    wnoutrefresh(main_win);
    return;
  }

  csh handle;
  cs_insn *insn;

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
    mvwprintw(main_win, 2, 2, "Error: Failed to initialize Capstone engine");
    wnoutrefresh(main_win);
    return;
  }

  int height, width;
  getmaxyx(main_win, height, width);
  int printable_rows = height - 2;

  size_t count =
      cs_disasm(handle, selectedFunction->code_bytes, selectedFunction->size,
                selectedFunction->vaddr, 0, &insn);

  if (count > 0) {
    for (size_t i = 0; i < (size_t)printable_rows; i++) {
      size_t idx = disasmScroll + i;
      if (idx >= count)
        break;

      int row = (int)i + 1;

      wattron(main_win, COLOR_PAIR(COLOR_PAIR_ADDR));
      mvwprintw(main_win, row, 2, "0x%08" PRIx64 ":", insn[idx].address);
      wattroff(main_win, COLOR_PAIR(COLOR_PAIR_ADDR));

      wattron(main_win, COLOR_PAIR(COLOR_PAIR_MNEMONIC));
      mvwprintw(main_win, row, 15, "%-8s", insn[idx].mnemonic);
      wattroff(main_win, COLOR_PAIR(COLOR_PAIR_MNEMONIC));

      draw_operands(main_win, row, 24, insn[idx].mnemonic, insn[idx].op_str,
                    width - 26, functionList);
    }
    cs_free(insn, count);
  } else {
    mvwprintw(main_win, 2, 2, "Failed to disassemble instructions");
  }
  cs_close(&handle);

  wnoutrefresh(main_win);
}

static void draw_status(WINDOW *status_win, const ElfContext *ctx,
                        const char *filepath) {
  if (!ctx || !filepath)
    return;

  int isPie = is_pie_enabled(ctx);
  int isCanary = is_canary_enabled(ctx);
  int isNx = is_nx_enabled(ctx);
  int relroState = is_relro_enabled(ctx);

  werase(status_win);
  wbkgd(status_win, COLOR_PAIR(COLOR_PAIR_STATUS));

  const char *filename = strrchr(filepath, '/');
  filename = (filename) ? filename + 1 : filepath;

  mvwprintw(status_win, 0, 1,
            " BinSpy by Dxrie | File: %s | Canary: ", filename);

  wattron(status_win, COLOR_PAIR(isCanary ? COLOR_PAIR_GOOD : COLOR_PAIR_BAD));
  wprintw(status_win, "%s", isCanary ? "Yes" : "No");
  wattroff(status_win, COLOR_PAIR(isCanary ? COLOR_PAIR_GOOD : COLOR_PAIR_BAD));

  wprintw(status_win, " | NX: ");

  wattron(status_win, COLOR_PAIR(isNx ? COLOR_PAIR_GOOD : COLOR_PAIR_BAD));
  wprintw(status_win, "%s", isNx ? "Yes" : "No");
  wattroff(status_win, COLOR_PAIR(isNx ? COLOR_PAIR_GOOD : COLOR_PAIR_BAD));

  wprintw(status_win, " | PIE: ");

  wattron(status_win, COLOR_PAIR(isPie ? COLOR_PAIR_GOOD : COLOR_PAIR_BAD));
  wprintw(status_win, "%s", isPie ? "Yes" : "No");
  wattroff(status_win, COLOR_PAIR(isPie ? COLOR_PAIR_GOOD : COLOR_PAIR_BAD));

  wprintw(status_win, " | RELRO: ");

  if (relroState == 2) {
    wattron(status_win, COLOR_PAIR(COLOR_PAIR_GOOD));
    wprintw(status_win, "Full");
    wattroff(status_win, COLOR_PAIR(COLOR_PAIR_GOOD));
  } else if (relroState == 1) {
    wattron(status_win, COLOR_PAIR(COLOR_PAIR_MID)); // Yellow/Cyan highlight
    wprintw(status_win, "Partial");
    wattroff(status_win, COLOR_PAIR(COLOR_PAIR_MID));
  } else {
    wattron(status_win, COLOR_PAIR(COLOR_PAIR_BAD));
    wprintw(status_win, "No");
    wattroff(status_win, COLOR_PAIR(COLOR_PAIR_BAD));
  }

  wnoutrefresh(status_win);
}

void tui_run(const ElfContext *ctx, const char *filepath) {
  if (!ctx)
    return;

  TuiFocus currentFocus = FOCUS_SIDEBAR;
  size_t disasmScroll = 0;

  ElfFunctionList functionList;
  size_t selectedIdx = 0;
  size_t scrollOffset = 0;
  elf_find_all_functions(ctx, &functionList);

  initscr();
  cbreak();
  noecho();
  keypad(stdscr, TRUE);
  curs_set(0);

  init_ncurses_colors();

  int max_x, max_y;
  getmaxyx(stdscr, max_y, max_x);

  int sidebar_width = 30;
  int status_height = 1;
  int main_height = max_y - status_height;
  int main_width = max_x - sidebar_width;

  WINDOW *sidebar_win = newwin(main_height, sidebar_width, 0, 0);
  WINDOW *main_win = newwin(main_height, main_width, 0, sidebar_width);
  WINDOW *status_win = newwin(status_height, max_x, max_y - 1, 0);

  keypad(status_win, TRUE);

  const ElfFunction *selectedFunction =
      (functionList.count > 0) ? &functionList.functions[selectedIdx] : NULL;

  draw_sidebar(sidebar_win, &functionList, selectedIdx, scrollOffset,
               currentFocus == FOCUS_SIDEBAR);
  draw_main(main_win, selectedFunction, disasmScroll,
            currentFocus == FOCUS_DISASM, &functionList);
  draw_status(status_win, ctx, filepath);
  doupdate();

  int running = 1;
  while (running) {
    int ch = wgetch(status_win);
    switch (ch) {
    case 'q':
    case 'Q':
      running = 0;
      break;

    case KEY_LEFT:
      currentFocus = FOCUS_SIDEBAR;
      break;

    case KEY_RIGHT:
      currentFocus = FOCUS_DISASM;
      break;

    case KEY_DOWN:
      if (currentFocus == FOCUS_SIDEBAR) {
        if (functionList.count > 0) {
          int printable_rows = main_height - 2;
          if (selectedIdx < functionList.count - 1) {
            selectedIdx++;
            if (selectedIdx >= scrollOffset + printable_rows) {
              scrollOffset++;
            }
          } else {
            selectedIdx = 0;
            scrollOffset = 0;
          }
          disasmScroll = 0;
        }
      } else {
        if (selectedFunction) {
          size_t total_insns = get_instruction_count(selectedFunction);
          int printable_rows = main_height - 2;

          if (total_insns > (size_t)printable_rows) {
            size_t max_scroll = total_insns - printable_rows;
            if (disasmScroll < max_scroll) {
              disasmScroll++;
            }
          }
        }
      }
      break;

    case KEY_UP:
      if (currentFocus == FOCUS_SIDEBAR) {
        if (functionList.count > 0) {
          int printable_rows = main_height - 2;
          if (selectedIdx > 0) {
            selectedIdx--;
            if (selectedIdx < scrollOffset) {
              scrollOffset--;
            }
          } else {
            selectedIdx = functionList.count - 1;
            scrollOffset = (functionList.count > (size_t)printable_rows)
                               ? functionList.count - printable_rows
                               : 0;
          }
          disasmScroll = 0;
        }
      } else {
        if (disasmScroll > 0) {
          disasmScroll--;
        }
      }
      break;

    case KEY_RESIZE:
      getmaxyx(stdscr, max_y, max_x);
      main_height = max_y - status_height;
      main_width = max_x - sidebar_width;

      wresize(sidebar_win, main_height, sidebar_width);
      wresize(main_win, main_height, main_width);
      mvwin(main_win, 0, sidebar_width);

      wresize(status_win, status_height, max_x);
      mvwin(status_win, max_y - 1, 0);
      break;
    }

    if (running) {
      selectedFunction = (functionList.count > 0)
                             ? &functionList.functions[selectedIdx]
                             : NULL;

      draw_sidebar(sidebar_win, &functionList, selectedIdx, scrollOffset,
                   currentFocus == FOCUS_SIDEBAR);
      draw_main(main_win, selectedFunction, disasmScroll,
                currentFocus == FOCUS_DISASM, &functionList);
      draw_status(status_win, ctx, filepath);
      doupdate();
    }
  }

  delwin(sidebar_win);
  delwin(main_win);
  delwin(status_win);
  endwin();

  elf_free_function_list(&functionList);
}
