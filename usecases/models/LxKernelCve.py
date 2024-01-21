#!/usr/bin/env python3
import requests, json, signal
from typing import Tuple
from bs4 import BeautifulSoup


def _req_timeout_handler(signum, frame):
    raise TimeoutError()

class LxKernelCve:
    @classmethod
    def parse_affected_versions(cls, affected_versions: str) -> Tuple[str, str]:
        affected_versions = affected_versions.strip().split(' to ')
        return [
            ('unk', 'unk'),
            (affected_versions[0], 'unk'),
            tuple(affected_versions)
        ][len(affected_versions)]


    def __init__(self, cveid: str, cvedata: dict):
        self.id = cveid.lstrip('dd=').lstrip('CVE-') # TODO: 'dd=' resolve
        # affected versions info
        self.affected_versions = LxKernelCve.parse_affected_versions(cvedata.get('affected_versions', 'unk to unk'))
        self.last_affected_version = cvedata.get('last_affected_version', self.affected_versions[1])

        self.backport = cvedata.get('backport', False)

        self.cwe = cvedata.get('cwe', 'Other')

        # commits info
        self.breaks = cvedata.get('breaks', '')
        self.fixes = cvedata.get('fixes', '')
        self.cmt_msg = cvedata.get('cmt_msg', '')

        self.last_modified = cvedata.get('last_modified', '')
        self.nvd_text = cvedata.get('nvd_text', '')

        self.reserved_year = int(self.id.split('-', 1)[0])

        # TODO: parse cvss3 and cvss2


    def cve(self) -> str:
        return 'CVE-' + self.id


    def ref_url(self, source: str) -> str:
        prefixes = {
            'Debian': 'https://security-tracker.debian.org/tracker/CVE-',
            'ExploitDB': 'https://www.exploit-db.com/search?cve=',
            'NVD': 'https://nvd.nist.gov/vuln/detail/CVE-',
            'Red Hat': 'https://access.redhat.com/security/cve/CVE-',
            'SUSE': 'https://www.suse.com/security/cve/CVE-',
            'Ubuntu': 'https://ubuntu.com/security/CVE-',

        }
        prefix = prefixes.get(source, '')
        if prefix == '':
            return ''
        return prefix + self.id


    def fixed_files(self, requests_timeout: int = 3) -> list[str]:
        if self.fixes == '':
            return []

        url = 'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit?id='
        try:
            signal.signal(signal.SIGALRM, _req_timeout_handler)
            signal.alarm(requests_timeout)
            soup = BeautifulSoup(requests.get(url + self.fixes).text, 'html.parser') # TODO errors handling

            diffstat = soup.find('table', { 'class': 'diffstat' })

            def _get_file(row) -> str:
                return row.find('td', { 'class': 'upd' }).string.strip()

            return [ _get_file(row) for row in diffstat.find_all('tr', recursive=False) ]
        except Exception as e:
            return []
        finally:
            signal.alarm(0)


    cve_source = 'https://raw.githubusercontent.com/nluedtke/linux_kernel_cves/master/data/kernel_cves.json'
    db = {}
    @classmethod
    def select(cls, cveid: str):
        return cls.db.get(cveid, None)

    @classmethod
    def insert(cls, cveid: str, cvedata: dict):
        cls.db[cveid] = LxKernelCve(cveid, cvedata)

    @classmethod
    def loadDb(cls) -> bool:
        try:
            kernel_cves = json.loads(requests.get(cls.cve_source).text) # TODO errors handling
            for cveid, cvedata in kernel_cves.items():
                LxKernelCve.insert(cveid, cvedata)
            return True
        except Exception as e:
            return False

    @classmethod
    def toList(cls) -> list:
        return list(cls.db.values())

