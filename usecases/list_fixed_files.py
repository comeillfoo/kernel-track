#!/usr/bin/env python3
import argparse, logging
from models.LxKernelCve import LxKernelCve


ENOENT = 2

def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser('list_fixed_files')
    p.add_argument('cve', help='CVE id')

    p.add_argument('-q', '--brief', action='store_true',
                   help='Print only warning/error messages')

    default_timeout = 5 # secs
    p.add_argument('-t', '--timeout', type=int, default=default_timeout,
        help=f'Connect and read timeout, default {default_timeout} seconds')
    return p


def main() -> int:
    args = parser().parse_args()
    cveid, brief, timeout = args.cve, args.brief, args.timeout

    logging.getLogger().setLevel('WARNING' if brief else 'INFO')
    logging.info(f'List fixed files for {cveid}')

    if not LxKernelCve.loadDb():
        logging.error('Linux Kernel CVEs data not loaded')
        return 1

    lxKernelCve = LxKernelCve.select(cveid)
    if not lxKernelCve:
        logging.error(f'cannot found vulnerability by CVE: {cveid}')
        return ENOENT

    if lxKernelCve.fixes == '':
        logging.warning('no files available')
        return ENOENT

    fixedFiles = lxKernelCve.fixed_files(timeout)
    if len(fixedFiles) == 0:
        logging.warning('no files were fixed')
        return ENOENT

    for fixedFile in fixedFiles:
        print(fixedFile)
    return 0


if __name__ == '__main__':
    exit(main())

