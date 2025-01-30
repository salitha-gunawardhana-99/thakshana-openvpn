# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -g

# Target executable
TARGET = xor_cipher_test

# Source files
SRCS = main.c xor_cipher.c

# Object files (automatically generated from source files)
OBJS = $(SRCS:.c=.o)

# Default target
all: $(TARGET)

# Link object files to create the executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

# Compile source files into object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up build files
clean:
	rm -f $(OBJS) $(TARGET)

# Run the executable
run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run