# UNIX makefile for mg_pwind module (mg_pwind.so)
#
# Build:
# make Makefile
#
# Cleanup:
# make clean
#
# Install:
# make install

MGYDBDIR=/usr/local/lib/yottadb/r130
MGPWINDINC=./

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
   MGPWINDOS = Linux
   CC = cc
   CCFLAGS += -fpic -DLINUX
   LINK += cc
   LINKFLAGS += -shared -rdynamic
endif
ifeq ($(UNAME_S),Darwin)
   MGPWINDOS = OSX
   CC = cc
   CCFLAGS += -fPIC -fno-common -DMACOSX -D_NOTHREADS -DDARWIN
   LINK += cc
   LINKFLAGS += -bundle -flat_namespace -undefined suppress
endif
ifeq ($(UNAME_S),FreeBSD)
   MGPWINDOS = FreeBSD
   CC = cc
   CCFLAGS += -DFREEBSD
   LINK = ld
   LINKFLAGS += -G
endif
ifeq ($(UNAME_S),AIX)
   MGPWINDOS = AIX
   CC = xlc_r
   CCFLAGS += -DAIX
   LINK = xlc_r
   LINKFLAGS += -G -H512 -T512 -bM:SRE -berok -bexpall -bnoentry
endif

ifndef MGPWINDOS
   $(error Cannot determine the OS type)
endif

# Build mg_pwind module
all : app

# Link the object file and dependent libraries into a binary
app : mg_pwind.o
	$(LINK) -o mg_pwind.so $(LINKFLAGS) mg_pwind.o

# Compile the source file into object file
mg_pwind.o : mg_pwind.c
	$(CC) -o mg_pwind.o $(CCFLAGS) -DMG_PWIND_DSO -I$(MGPWINDINC) -c mg_pwind.c

# Install mg_pwind module
install :
	cp mg_pwind.so $(MGYDBDIR)/mg_pwind.so
	cp mg_pwind.xc $(MGYDBDIR)/mg_pwind.xc

# Clean target
clean :
	rm -rf mg_pwind.so mg_pwind.o



