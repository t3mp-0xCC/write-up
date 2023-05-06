#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

if len(argv) >= 2 and argv[1] == "r":
    p = remote("netcat-pwn.wanictf.org", 9001)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b main
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


def solve():
    p.recvuntil("+\n\n")
    left = p.recvuntil(" + ").decode().rstrip(" + ")
    right = p.recvuntil(" =").decode().rstrip(" =")
    answer = int(left) + int(right)
    p.sendline(str(answer))

for i in range(3):
    solve()

p.interactive()
