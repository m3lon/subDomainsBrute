# -*- coding:utf-8 -*-
#! /usr/local/bin python3

import dns.resolver

resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ["223.5.5.5", "223.6.6.6", "119.29.29.29", "182.254.116.116"]
try:
    a = resolver.query("www.qq.com", "A")
    for i in a:
        print(i)

    cname = resolver.query("www.qq.com", 'cname')
    print(cname[0].target.to_unicode().strip())
except dns.resolver.NXDOMAIN:
    pass



