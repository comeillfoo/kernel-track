#!/usr/bin/env python3
from typing import Tuple
import requests, json
from bs4 import BeautifulSoup


class LxKernelCve:
    @classmethod
    def parse_affected_versions(cls, affected_versions: str) -> Tuple[str, str]:
        return ''


    def __init__(self, cveid: str, cvedata: dict):
        self.id = cveid.lstrip('CVE-')
        self.affected_versions = LxKernelCve.parse_affected_versions(cvedata.get('affected_versions', 'unk to unk'))

        # hash commits
        self.breaks = cvedata.get('breaks', '')
        self.fixes = cvedata.get('fixes', '')

        self.last_modified = cvedata.get('last_modified', '')
        self.nvd_text = cvedata.get('nvd_text', '')


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


    def fixed_files(self) -> list[str]:
        if self.fixes == '':
            return []

        url = 'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit?id='

        soup = BeautifulSoup(requests.get(url + self.fixes).text, 'html.parser') # TODO errors handling

        diffstat = soup.find('table', { 'class': 'diffstat' })

        def _get_file(row) -> str:
            return row.find('td', { 'class': 'upd' }).string.strip()

        return [ _get_file(row) for row in diffstat.find_all('tr', recursive=False) ]


    cve_source = 'https://raw.githubusercontent.com/nluedtke/linux_kernel_cves/master/data/kernel_cves.json'
    db = {}
    @classmethod
    def select(cls, cveid: str):
        return cls.db.get(cveid, None)

    @classmethod
    def insert(cls, cveid: str, cvedata: dict):
        cls.db[cveid] = LxKernelCve(cveid, cvedata)

    @classmethod
    def loadDb(cls):
        kernel_cves = json.loads(requests.get(cls.cve_source).text) # TODO errors handling
        for cveid, cvedata in kernel_cves.items():
            LxKernelCve.insert(cveid, cvedata)
