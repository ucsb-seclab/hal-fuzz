# Unicorn Engine
# By Nguyen Anh Quynh <aquynh@gmail.com>, 2015

include ./config.mk

UNAME_S := $(shell uname -s)

LIBDIR = ../../unicorn_mode/unicorn-1.0.1/
BIN_EXT = .so
AR_EXT = a

# Verbose output?
V ?= 1

CFLAGS += -shared -fpic -Wall -Werror

LDFLAGS += -shared -L$(LIBDIR) -lunicorn -lpthread -lm -DDEBUG
ifeq ($(UNAME_S), Linux)
LDFLAGS += -lrt
endif

LDLIBS += -lpthread -lunicorn -lm

ifneq ($(CROSS),)
CC = $(CROSS)gcc
endif

ifeq ($(UNICORN_ASAN),yes)
CC = clang 
CXX = clang++
AR = llvm-ar
CFLAGS += -fsanitize=address -fno-omit-frame-pointer
LDFLAGS := -fsanitize=address ${LDFLAGS}
endif

# Cygwin?
ifneq ($(filter CYGWIN%,$(UNAME_S)),)
CFLAGS := $(CFLAGS:-fPIC=)
LDLIBS += -lssp
BIN_EXT = .exe
AR_EXT = a
# mingw?
else ifneq ($(filter MINGW%,$(UNAME_S)),)
CFLAGS := $(CFLAGS:-fPIC=)
BIN_EXT = .exe
AR_EXT = a
endif

ifeq ($(UNICORN_STATIC),yes)
ifneq ($(filter MINGW%,$(UNAME_S)),)
ARCHIVE = $(LIBDIR)/unicorn.$(AR_EXT)
else ifneq ($(filter CYGWIN%,$(UNAME_S)),)
ARCHIVE = $(LIBDIR)/libunicorn.$(AR_EXT)
else
ARCHIVE = $(LIBDIR)/libunicorn.$(AR_EXT)
endif
endif

.PHONY: all clean

SOURCES = native_hooks.c nvic.c timer.c interrupt_triggers.c util.c

BINS = $(SOURCES:.c=$(BIN_EXT))
OBJS = $(SOURCES:.c=.o)

native_hooks.so: $(OBJS)
	$(CC) $^ $(LDFLAGS) -o $@

all: native_hooks.so

$(BINS): $(OBJS)

clean:
	rm -rf *.o $(BINS)

%$(BIN_EXT): %.o
	@mkdir -p $(@D)
ifeq ($(V),0)
ifeq ($(UNICORN_SHARED),yes)
	$(call log,LINK,$(notdir $@))
	@$(link-dynamic)
endif
ifeq ($(UNICORN_STATIC),yes)
ifneq ($(filter MINGW%,$(UNAME_S)),)
	$(call log,LINK,$(notdir $(call staticname,$@)))
	@$(link-static)
endif
endif
else
ifeq ($(UNICORN_SHARED),yes)
	$(link-dynamic)
endif
ifeq ($(UNICORN_STATIC),yes)
ifneq ($(filter MINGW%,$(UNAME_S)),)
	$(link-static)
endif
endif
endif

%.o: %.c
	@mkdir -p $(@D)
ifeq ($(V),0)
	$(call log,CC,$(@:%=%))
	@$(compile)
else
	$(compile)
endif


define link-dynamic
	$(CC) $< $(LDFLAGS) -o $@
endef


define link-static
	$(CC) $< $(ARCHIVE) $(LDFLAGS) -o $(call staticname,$@)
endef


staticname = $(subst $(BIN_EXT),,$(1)).static$(BIN_EXT)

define log
	@printf "  %-7s %s\n" "$(1)" "$(2)"
endef

define compile
	${CC} ${CFLAGS} -c $< -o $@
endef
