# Compiler and flags
CC      := gcc
CFLAGS  := -Wall -Wextra -Werror -Iinclude -std=c11 -g
LDFLAGS :=

# Directory structure
SRC_DIR := src
OBJ_DIR := obj
INC_DIR := include

# Target executable name
TARGET  := elf-analyzer

# Automatically collect all .c files in src/ and map them to obj/.o files
SRCS    := $(wildcard $(SRC_DIR)/*.c)
OBJS    := $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Default target: build the executable
all: $(TARGET)

# Link object files into the final executable
$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(OBJS) $(LDFLAGS) -o $@
	@echo "Build successful: $@"

# Compile source files into object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build artifacts
clean:
	rm -rf $(OBJ_DIR) $(TARGET)
	@echo "Cleaned build artifacts."

.PHONY: all clean
