# Makefile - DSCourier BOF for x86 + x64 via MinGW-w64
#
# IMPORTANT: do NOT add -ffunction-sections / -fdata-sections. Cobalt Strike
# 4.12's BOF loader only recognises a single consolidated .text section and
# rejects object files that only contain per-function .text$<name> sections
# with "No .text section in object file".
#
# Default toolchain:
#   CC64 = x86_64-w64-mingw32-gcc
#   CC32 = i686-w64-mingw32-gcc
#
# If your MinGW is 64-bit only but supports multilib, set CC32 to -m32:
#   make CC32="x86_64-w64-mingw32-gcc -m32"
#
# Outputs:
#   dscourier.x64.o   - inline-exec from a 64-bit beacon
#   dscourier.x86.o   - inline-exec from a 32-bit beacon

CC64 ?= x86_64-w64-mingw32-gcc
CC32 ?= i686-w64-mingw32-gcc

CFLAGS = -Os -c -Wall -Wextra -Wno-unused-parameter -Wno-unused-function \
         -fno-ident -fno-asynchronous-unwind-tables -fno-stack-protector \
         -DBOF

HEADERS = dscourier.h beacon.h iids.h

.PHONY: all clean

all: dscourier.x64.o dscourier.x86.o

dscourier.x64.o: dscourier.c $(HEADERS)
	$(CC64) $(CFLAGS) -o $@ $<
	@echo "[+] $@"

dscourier.x86.o: dscourier.c $(HEADERS)
	$(CC32) $(CFLAGS) -o $@ $<
	@echo "[+] $@"

clean:
	rm -f dscourier.x64.o dscourier.x86.o