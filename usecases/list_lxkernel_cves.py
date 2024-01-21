#!/usr/bin/env python3
import argparse, logging
from models.LxKernelCve import LxKernelCve


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser('list_lxkernel_cves')
    p.add_argument('-l', '--count', action='store_true',
                   help='Switch to counting mode, prints only amount')
    return p


def main() -> int:
    should_count = parser().parse_args().count

    if not LxKernelCve.loadDb():
        logging.error(f'Linux Kernel CVEs data not loaded')
        return 1

    lxKernelCves = LxKernelCve.toList()
    if should_count:
        print(len(lxKernelCves))
    else:
        for cveid in map(LxKernelCve.cve, lxKernelCves):
            print(cveid)
    return 0


if __name__ == '__main__':
    exit(main())
