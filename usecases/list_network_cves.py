#!/usr/bin/env python3
import argparse, logging
from models.LxKernelCve import LxKernelCve


ENOENT = 2


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser('list_network_cves')
    p.add_argument('-l', '--count', action='store_true',
                   help='Switch to counting mode, prints only amount')
    p.add_argument('-q', '--brief', action='store_true',
                   help='Print only warning/error messages')
    p.add_argument('-d', '--debug', type=str,
                   help='Check only one CVE')
    return p


possible_paths = [
    'drivers/net/',
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
    if not text:
        return False
    words = text.split()
    for possible_word in possible_words:
        if possible_word in words:
            return True
    return is_files_about_network(words)


def confirm(prompt: str) -> bool:
    while True:
        try:
            t = input(prompt).strip().lower()
            if t not in ('y', 'n'):
                raise ValueError
            return True if t == 'y' else False
        except Exception as e:
            print(f'Malformed input: \'{t}\'')


def interactive_check(predicate):
    def wrapper(lxKernelCve: LxKernelCve) -> bool:
        result = predicate(lxKernelCve)
        msg = f'Confirm result ({result}) for {lxKernelCve.cve()} [Y/n]: '
        if not result and not confirm(msg):
            result = not result
        print(f'Confirmed {result} for {lxKernelCve.cve()}')
        return result

    return wrapper


# @interactive_check
def is_network_cve(lxKernelCve: LxKernelCve) -> bool:
    return is_text_about_network(lxKernelCve.cmt_msg) \
        or is_text_about_network(lxKernelCve.nvd_text) \
        or is_files_about_network(lxKernelCve.fixed_files())


def main() -> int:
    args = parser().parse_args()
    should_count, brief, debug_cve = args.count, args.brief, args.debug
    logging.getLogger().setLevel('WARNING' if brief else 'INFO')

    if not LxKernelCve.loadDb():
        logging.error(f'Linux Kernel CVEs data not loaded')
        return 1

    if debug_cve is not None and debug_cve != '':
        debug_cve = debug_cve.strip()
        lxKernelCve = LxKernelCve.select(debug_cve)
        if not lxKernelCve:
            logging.error(f'cannot found vaulnerability by CVE: {debug_cve}')
            return ENOENT
        print(debug_cve, is_network_cve(lxKernelCve))
        return 0

    netLxKernelCve = list(filter(is_network_cve, LxKernelCve.toList()))
    if should_count:
        print(len(netLxKernelCve))
    else:
        for cveid in map(LxKernelCve.cve, netLxKernelCve):
            print(cveid)
    return 0


if __name__ == '__main__':
    exit(main())