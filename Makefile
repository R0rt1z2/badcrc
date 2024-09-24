CC = gcc
CFLAGS = -Wall -O2
TARGET = badcrc
SRC = badcrc.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET) $(INPUT) $(OUTPUT) 
