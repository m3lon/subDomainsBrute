# -*- coding:utf-8 -*-
import sys
import dns.resolver
from lib.consle_width import getTerminalSize
import os

console_width = getTerminalSize()[0] - 2

def is_intranet(ip):
    ret = ip.split('.')
    if len(ret) != 4:
        return True
    if ret[0] == '10':
        return True
    if ret[0] == '172' and 16 <= int(ret[1]) <= 32:
        return True
    if ret[0] == '192' and ret[1] == '168':
        return True
    return False

def print_msg(msg=None, left_align=True, line_feed=False):
    if left_align:
        sys.stdout.write('\r' + msg + ' ' * (console_width - len(msg)))
    else:  # right align
        sys.stdout.write('\r' + ' ' * (console_width - len(msg)) + msg)
    if line_feed:
        sys.stdout.write('\n')
    sys.stdout.flush()

def test_server(server, dns_servers):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.lifetime = resolver.timeout = 6.0
    try:
        resolver.nameservers = [server]
        answers = resolver.query('public-dns-a.baidu.com')    # test lookup an existed domain
        if answers[0].address != '180.76.76.76':
            raise Exception('Incorrect DNS response')
        try:
            resolver.query('test.bad.dns.lijiejie.com')    # Non-existed domain test
            with open('bad_dns_servers.txt', 'a') as f:
                f.write(server + '\n')
            print_msg('[+] Bad DNS Server found %s' % server)
        except:
            dns_servers.append(server)
        print_msg('[+] Server %s < OK >   Found %s' % (server.ljust(16), len(dns_servers)))
    except:
        print_msg('[+] Server %s <Fail>   Found %s' % (server.ljust(16), len(dns_servers)))


def load_dns_servers():
    print("[+] Validate DNS Servers")
    dns_servers = []

    for server in open("dict/dns_servers.txt").readlines():
        server = server.strip()
        # 多进程处理
        if server:
            test_server(server, dns_servers)

    dns_count = len(dns_servers)
    print('\n[+] %s available DNS Servers found in total' % dns_count)
    if dns_count == 0:
        print('[ERROR] No DNS Servers available!')
        sys.exit(-1)

    return dns_servers

def load_next_subs(full_scan):
    next_subs = []
    _set = set()
    _file = 'dict/next_sub_full.txt' if full_scan else 'dict/next_sub.txt'

    # 下面的这些似乎只有{alphnum}用到了
    with open(_file) as f:
        for line in f:
            sub = line.strip()
            if sub and sub not in next_subs:
                tmp_set = {sub}
                while tmp_set:
                    item = tmp_set.pop()
                    if item.find('{alphnum}') >= 0:
                        # 只允许本类和其子类访问
                        for _letter in 'abcdefghijklmnopqrstuvwxyz0123456789':
                            tmp_set.add(item.replace('{alphnum}', _letter, 1))
                    elif item.find('{alpha}') >= 0:
                        for _letter in 'abcdefghijklmnopqrstuvwxyz':
                            tmp_set.add(item.replace('{alpha}', _letter, 1))
                    elif item.find('{num}') >= 0:
                        for _letter in '0123456789':
                            tmp_set.add(item.replace('{num}', _letter, 1))
                    elif item not in _set:
                        _set.add(item)
                        next_subs.append(item)
    return next_subs

def get_out_file_name(target, args):
    if args.output:
        outfile = args.output
    else:
        _name = os.path.basename(args.file).replace('subnames', '')
        if _name != '.txt':
            _name = '_' + _name
        outfile = target + _name if not args.full_scan else target + '_full' + _name
    return outfile

# signal.signal会传递两个参数 sig和frame
def user_abort(sig, frame):
    exit(-1)
