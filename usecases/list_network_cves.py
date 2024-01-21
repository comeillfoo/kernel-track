#!/usr/bin/env python3
import argparse, logging
from models.LxKernelCve import LxKernelCve


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser('list_network_cves')
    p.add_argument('-l', '--count', action='store_true',
                   help='Switch to counting mode, prints only amount')
    p.add_argument('-q', '--brief', action='store_true',
                   help='Print only warning/error messages')
    return p


possible_paths = [
    'drivers/net/'
    'net/',
]

def is_file_about_network(path: str) -> bool:
    path = path.strip()
    if not path:
        return False
    for possible_path in possible_paths:
        if path.startswith(possible_path):
            return True
    return False

def is_files_about_network(fixed_files: list[str]) -> bool:
    for fixed_file in fixed_files:
        if is_file_about_network(fixed_file):
            return True
    return False

possible_words = [
    'socket', 'tcp', 'udp', 'ethernet', 'network', 'networking', 'bluetooth',
    'ceph', 'rxrpc', 'rose', 'vswitch', 'mptcp', 'mpls', 'sctp', 'ipv4', 'ipv6',
    'ip', 'devlink', 'B.A.T.M.A.N', 'ax25', # requires testing
]

def is_text_about_network(text: str) -> bool:
    text = text.strip().lower().strip(':')
    # logging.info(f'\t{text}\n')
    if not text:
        return False
    words = text.split()
    for possible_word in possible_words:
        if possible_word in words:
            return True
    return False


def is_network_cve(lxKernelCve: LxKernelCve) -> bool:
    logging.info(lxKernelCve.cve())
    return is_text_about_network(lxKernelCve.cmt_msg) \
        or is_text_about_network(lxKernelCve.nvd_text) \
        or is_files_about_network(lxKernelCve.fixed_files())


def main() -> int:
    args = parser().parse_args()
    should_count, brief = args.count, args.brief
    logging.getLogger().setLevel('WARNING' if brief else 'INFO')

    if not LxKernelCve.loadDb():
        logging.error(f'Linux Kernel CVEs data not loaded')
        return 1

    netLxKernelCve = list(filter(is_network_cve, LxKernelCve.toList()))
    if should_count:
        print(len(netLxKernelCve))
    else:
        for cveid in map(LxKernelCve.cve, netLxKernelCve):
            print(cveid)
    return 0


if __name__ == '__main__':
    exit(main())