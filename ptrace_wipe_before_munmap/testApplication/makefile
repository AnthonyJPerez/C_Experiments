CC          = gcc
CFLAGS      = -O3 -g
LDFLAGS     = 

OUTDIR = ../bin
SRCDIR = src
TARGET = $(OUTDIR)/testApplication
SOURCES = $(shell echo $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

clean:
	rm -f $(OBJECTS) $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)


