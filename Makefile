# --- Compiler and Flags ---
CC = gcc
# CFLAGS: -g = debugging symbols, -Wall = all warnings, -pthread = for pthreads
# -Iinclude = "look in /include for .h files"
CFLAGS = -g -Wall -pthread -Iinclude
# LDFLAGS: -pthread = link pthread library
LDFLAGS = -pthread

# --- Directories ---
SRC_DIR = src
BUILD_DIR = build
BIN_DIR = bin

# --- Executables ---
TARGETS = $(BIN_DIR)/nm $(BIN_DIR)/ss $(BIN_DIR)/client

# --- Source Files ---
# Find all .c files in the utils directory
UTILS_SRCS = $(wildcard $(SRC_DIR)/utils/*.c)
# Get the corresponding .o (object) files, but in BUILD_DIR
UTILS_OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(UTILS_SRCS))

# Name Server (nm) sources and objects
NM_SRCS = $(wildcard $(SRC_DIR)/nm/*.c)
NM_OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(NM_SRCS))

# Storage Server (ss) sources and objects
SS_SRCS = $(wildcard $(SRC_DIR)/ss/*.c)
SS_OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SS_SRCS))

# Client (client) sources and objects
CLIENT_SRCS = $(wildcard $(SRC_DIR)/client/*.c)
CLIENT_OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(CLIENT_SRCS))

# --- Rules ---

# Default rule: build all targets
all: $(TARGETS)

# Rule to build the Name Server executable
$(BIN_DIR)/nm: $(NM_OBJS) $(UTILS_OBJS)
	@mkdir -p $(BIN_DIR) # Ensure bin directory exists
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Rule to build the Storage Server executable
$(BIN_DIR)/ss: $(SS_OBJS) $(UTILS_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Rule to build the Client executable
$(BIN_DIR)/client: $(CLIENT_OBJS) $(UTILS_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Generic rule to compile any .c file from src/ to an .o file in build/
# $< = the first prerequisite (.c file)
# $@ = the target (.o file)
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(@D) # Ensure the build sub-directory exists (e.g., build/nm)
	$(CC) $(CFLAGS) -c $< -o $@

# --- Cleanup ---
clean:
	@(rm -rf $(BUILD_DIR) $(BIN_DIR))

.PHONY: all clean
