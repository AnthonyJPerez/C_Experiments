CC          = gcc -std=c99
CFLAGS      = -O3 -g -D_GNU_SOURCE
LDFLAGS     = 

OUTDIR = ../bin
SRCDIR = src
TARGET = $(OUTDIR)/ptraceWiper
SOURCES = $(shell echo $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

clean:
	rm -f $(OBJECTS) $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)


