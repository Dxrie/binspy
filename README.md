# BinSpy

BinSpy is a terminal-based binary analysis tool designed for inspecting and analyzing 64-bit ELF binaries. It provides an intuitive text-based user interface (TUI) and robust parsing capabilities to uncover security mitigations and discover functions.

## Features

- **64-Bit ELF Parsing:** Core parsing and validation of 64-bit ELF binary files.
- **Robust Function Discovery:** Automatically locates and extracts functions within the binary, including robust fallback logic for segmenting and analyzing **stripped binaries** (even without section headers or symbol tables).
- **Interactive Ncurses TUI:** A full-featured text user interface offering:
  - A side pane for function and symbol navigation.
  - A main pane for viewing disassembled machine code.
  - A bottom status bar displaying binary information.
- **Security Mitigation Detection:** Checks the binary for common compile-time security features, including:
  - **PIE** (Position Independent Executable)
  - **NX** (No-eXecute) bit
  - **Canaries** (Stack Smashing Protection)
  - **RELRO** (Relocation Read-Only) - distinguishes between partial and full RELRO.
  - Detection of **Stripped** binaries.
- **Disassembly Engine Integration:** Extracts machine code bytes and virtual addresses to render assembly output for discovered functions.
- **Header Information Display:** Quick extraction and display of core ELF header metadata.

Another project made for fun prob gonna update this README in the future.
