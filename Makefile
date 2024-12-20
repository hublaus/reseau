CC = gcc
CFLAGS ?= -Wextra -Werror
LDLIBS ?= -lpcap

INCLUDE_PATH = ./include

TARGET   = analyseur
SRCDIR   = src
OBJDIR   = obj
BINDIR   = bin


SOURCES  := $(wildcard $(SRCDIR)/*.c)
INCLUDES := $(wildcard $(INCLUDE_PATH)/*.h)
OBJECTS  := $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)


all : $(BINDIR)/$(TARGET)
	@echo "Liens effectués!"

$(BINDIR)/$(TARGET): $(OBJECTS) $(LDLIBS) 
	mkdir -p $(BINDIR)
	$(CC) -o $@ $^ $(CFLAGS)
	@echo "Liens analyseur effectués!"


$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	mkdir -p $(OBJDIR)
	$(CC) -o $@ -c $< $(CFLAGS) -I$(INCLUDE_PATH)


.PHONY: clean
clean :
	rm -f $(OBJDIR)/*.o
	rm -f $(BINDIR)/$(TARGET)