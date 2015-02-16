CC          = gcc
CFLAGS      = -fPIC -O3 -g
LDFLAGS     = -shared

OUTDIR = ../bin
SRCDIR = src
TARGET = $(OUTDIR)/libTest.so
SOURCES = $(shell echo $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

clean:
	rm -f $(OBJECTS) $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)


