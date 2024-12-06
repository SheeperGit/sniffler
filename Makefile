# compiler + flags #
CC = gcc
CFLAGS = -Wall -g

# DIRS #
SRC_DIR = .
TYPES_DIR = types

# src files #
SRC = $(SRC_DIR)/sniffler.c $(SRC_DIR)/log_utils.c \
      $(wildcard $(TYPES_DIR)/*.c)

# .h files #
INCLUDES = -I$(SRC_DIR) -I$(TYPES_DIR)

# .o files #
OBJ = $(SRC:.c=.o)

# exe name #
EXEC = sniffler

# Default tgt for make #
all: $(EXEC)

# Link .o files to create exe #
$(EXEC): $(OBJ)
	$(CC) $(OBJ) -o $(EXEC)

# Compile files #
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# rm .o, sniffler files #
clean:
	rm -f $(OBJ) $(EXEC)

# Rebuild the project (clean + make) #
rebuild: clean all

.PHONY: all clean rebuild
