CC          = gcc -std=c99
CFLAGS      = -O3 -g -D_GNU_SOURCE
LDFLAGS     = -ldl

OUTDIR = ../bin
SRCDIR = src
TARGET = $(OUTDIR)/Parser
SOURCES = $(shell echo $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

clean:
	rm -f $(OBJECTS) $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)


