# -*- coding:utf-8 -*-

# author m3lon

from lib.cmdline import parse_args
from lib.common import load_dns_servers, load_next_subs, user_abort,print_msg,get_out_file_name, is_intranet
import time
import os
import multiprocessing
import signal
import sys
import gevent
import glob
import re
from gevent import monkey
monkey.patch_all()
from gevent.queue import PriorityQueue
import dns.resolver



# 一鼓作气，再而衰，三而竭
class SubNameBrute():
    def __init__(self, args, process_num, dns_servers, scan_count, found_count, queue_size_list,tmp_dir):
        self.args = args
        self.process_num = process_num
        self.scan_count = scan_count
        self.scan_count_local = 0
        self.found_count = found_count
        self.found_count_local = 0
        self.queue_size_list = queue_size_list
        self.local_time = time.time()
        self.tmp_dir = tmp_dir

        self.dns_servers = dns_servers
        self.dns_count = len(self.dns_servers)
        self.resolvers = [dns.resolver.Resolver(configure=False) for _ in range(self.args.threads)]
        self.ex_resolver = dns.resolver.Resolver(configure=False)
        self.ex_resolver.nameservers = dns_servers
        for _r in self.resolvers:
            _r.lifetime = _r.timeout = 6.0

        self.queue = PriorityQueue()
        self.priority = 0

        self._load_sub_names()
        self.found_subs = set()
        self.outfile = open('%s/%s_part_%s.txt' % (tmp_dir, args.domain, process_num), 'w')

    # 从字典中加载具有不同优先级的子域名
    def _load_sub_names(self):
        """
        1. 加载字典文件
            1. 判断是否为全扫描
            2. 判断是否指定字典文件
        2. 读取字典文件
            1. 去重: 利用set集合加判断
            2. 通配符处理：
                1. 通配符对应的集合如：{alpha}替换为^[a-z]$
                2. 冗余去除：既然通配符已经存在a-z，所以可以去除字典中a-z的字段
        3. 将合法字段存入queue队列中
        :return: 具有优先级和字典字段的队列 queue：(1, "www")
        """


        if self.args.full_scan and self.args.file == 'subnames.txt':
            _file = 'dict/subnames_full.txt'
        else:
            if os.path.exists(self.args.file):
                _file = self.args.file
            elif os.path.exists('dict/%s' % self.args.file):
                _file = 'dict/%s' % self.args.file
            else:
                print_msg('[ERROR] Names file not found: %s' % self.args.file)
                exit(-1)

        normal_lines = []
        lines = set()
        with open(_file) as f:
            # python2.3已经不推荐f.xreadlines这种方式，之后file本身就是可迭代，不需要xreadlines返回一个iter(file)
            for line in f:
                sub = line.strip()
                # 下面这三行只用于去重
                if not sub or sub in lines:
                    continue
                lines.add(sub)

                normal_lines.append(sub)

        for item in normal_lines[self.process_num::self.args.process]:
            self.priority += 1
            self.queue.put((self.priority, item))

        # 调试
        # if process_num == 0:
        #     print("[+] 待扫描序列 %s 个 %s：" % ( len(self.queue),str(self.queue)))

    def _scan(self, j):
        """
        1. dns.nameserver设置：给每个协程分配dns解析地址，根据dns_count均分即可
        2. 读取队列中的待扫描域名
            1. 去重 found_subs 如果已扫描就直接跳过
        3. dns.resolver.query()查询
            1. ip地址处理：内网地址；回环地址
            2. cname别名查询: 查找到别名后，再次query查询ip地址
        :param j:
        :return:
        """
        self.resolvers[j].nameservers = [self.dns_servers[j % self.dns_count]]

        # 调试
        # if j == 0:
        #     print("[+] process-%s scanning" % self.process_num)
        #     print("[+] dns解析地址为：" + str(self.resolvers[j].nameservers))

        while not self.queue.empty():

            item = self.queue.get(timeout=3.0)[1]
            self.scan_count_local += 1
            if time.time() - self.local_time > 3.0:
                self.scan_count.value += self.scan_count_local
                self.scan_count_local = 0
                # 每个进程队列的长度，即保存剩余长度
                self.queue_size_list[self.process_num] = self.queue.qsize()

            try:
                sub = item
                if sub in self.found_subs:
                    continue


                cur_sub_domain = sub + '.' + self.args.domain
                _sub = sub.split('.')[-1]
                try:
                    answers = self.resolvers[j].query(cur_sub_domain)
                except dns.resolver.NoAnswer as e:
                    answers = self.ex_resolver.query(cur_sub_domain)
                if answers:
                    self.found_subs.add(sub)
                    ips = ",".join([answer.address for answer in answers])
                    # 调试
                    # if j == 0:
                    #     print_msg("[+] process-%s scanning" % self.process_num)
                    #     print_msg("[+] 存在子域名：%s ;  剩余待扫描数量为：%s " % (cur_sub_domain, len(self.queue)))

                    # 一些特殊地址的处理 公共DNS 回环地址
                    if ips in ['1.1.1.1', '127.0.0.1', '0.0.0.0']:
                        continue

                    # 判断是否为内网地址
                    if self.args.i and is_intranet(answers[0].address):
                        continue

                    try:
                        # 查询别名
                        answers = self.resolvers[j].query(cur_sub_domain, 'cname')
                        # to_unicode为dns模块中定义的函数 用于将Name对象转换为unicode字符串
                        cname = answers[0].target.to_unicode().rstrip('.')
                        if cname.endswith(self.target) and cname not in self.found_subs:
                            self.found_subs.add(cname)
                            cname_sub = cname[:len(cname) - len(self.target) - 1]  # new sub
                            self.queue.put((0, cname_sub))

                    except:
                        pass

                    self.found_count_local += 1
                    # 应该是一些用于统计的信息 为了减小开销 每三秒统计一次
                    if time.time() - self.local_time > 3.0:
                        self.found_count.value += self.found_count_local
                        self.found_count_local = 0
                        self.queue_size_list[self.process_num] = self.queue.qsize()
                        self.local_time = time.time()

                    self.outfile.write(cur_sub_domain.ljust(30) + '\t' + ips + '\n')
                    self.outfile.flush()

            except (dns.resolver.NXDOMAIN, dns.name.EmptyLabel) as e:
                pass
            except (dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
                pass
            except Exception as e:
                import traceback
                traceback.print_exc()
                with open('errors.log', 'a') as errFile:
                    errFile.write('[%s] %s %s\n' % (type(e), cur_sub_domain, str(e)))

    def run(self):
        coroutines = [gevent.spawn(self._scan, i) for i in range(self.args.threads)]
        gevent.joinall(coroutines)




def run_process(args, process_num, dns_servers, scan_count, found_count, queue_size_list, tmp_dir):
    # 键盘中断 <ctrl+c> 经常会用到。默认动作为终止进程
    signal.signal(signal.SIGINT, user_abort)
    # 每个进程生成自己的subNameBrute类
    s = SubNameBrute(args=args, process_num=process_num, dns_servers=dns_servers,
                     scan_count = scan_count, found_count = found_count, queue_size_list = queue_size_list,
                     tmp_dir = tmp_dir
                     )
    s.run()

if __name__ == '__main__':
    args = parse_args()
    start_time = time.time()

    tmp_dir = "tmp/%s_%s" % (args.domain, int(time.time()))
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)

    # 其中对于多进程，multiprocessing.freeze_support()语句在windows系统上是必须的，这是因为windows的API不包含fork()等函数。
    multiprocessing.freeze_support()
    dns_servers = load_dns_servers()
    next_subs = load_next_subs(args.full_scan)

    scan_count = multiprocessing.Value('i', 0)
    found_count = multiprocessing.Value('i',0)
    queue_size_list = multiprocessing.Array('i', args.process)

    print('[+] Init %s scan process.' % args.process)

    all_process = []

    try:
        for process_num in range(args.process):
            p = multiprocessing.Process(target=run_process,
                                        args=(args, process_num, dns_servers,
                                              scan_count, found_count, queue_size_list,
                                              tmp_dir)
                                        )
            all_process.append(p)
            p.start()
        while all_process:
            for p in all_process:
                if not p.is_alive():
                    all_process.remove(p)

            left_counts = 0
            for c in queue_size_list:
                left_counts += c
            msg = '[*] %s found, %s scanned in %.1f seconds, %s groups left' % (
                found_count.value, scan_count.value, time.time() - start_time, left_counts)
            print_msg(msg)
            time.sleep(1.0)

    except KeyboardInterrupt as e:
        for p in all_process:
            p.terminate()
        print('[ERROR] User aborted the scan!')

    msg = '[+] All Done. %s found, %s scanned in %.1f seconds.' % (
        found_count.value, scan_count.value, time.time() - start_time)
    print_msg(msg, line_feed=True)
    out_file_name = get_out_file_name(args.domain, args)
    with open(out_file_name, 'w') as f:
        for _file in glob.glob(tmp_dir + '/*.txt'):
            with open(_file, 'r') as tmp_f:
                content = tmp_f.read()
            f.write(content)
    print('[+] The output file is %s' % out_file_name)

