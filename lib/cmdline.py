import argparse
import sys

def parse_args():
    parser = argparse.ArgumentParser(usage=" %(prog)s -d target.com [options]")

    parser.add_argument('-d', dest='domain', action='store',
                        help="The domain's name to be scanned")
    parser.add_argument('-f', dest="file" , default="subnames.txt",
                        help="File contains new line delimited subs, default is subnames.txt." )
    parser.add_argument('--full', dest="full_scan", default=False, action='store_true',
                        help="Full scan, NAMES FILE subnames_full.txt will be used to brute")
    # 忽略内网
    parser.add_argument('-i', '--ignore-intranet', dest='i', default=False, action='store_true',
                      help='Ignore domains pointed to private IPs')
    parser.add_argument('-t', '--threads', dest='threads', default=150, type=int,
                      help='Num of scan threads, 200 by default')
    parser.add_argument('-p', '--process', dest='process', default=6, type=int,
                      help='Num of scan Process, 6 by default')
    parser.add_argument('-o', '--output', dest='output', default=None,
                      help='Output file name. default is {target}.txt')

    args =  parser.parse_args()
    if not args.domain:
        parser.print_help()
        sys.exit(0)

    return args
