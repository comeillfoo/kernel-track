#!/usr/bin/env python3
from typing import Tuple


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


    db = {}
    @classmethod
    def __getitem__(cls, cveid: str):
        return cls.db.get(cveid, None)

    @classmethod
    def __setitem__(cls, cveid: str, cvedata: dict):
        cls.db[cveid] = LxKernelCve(cveid, cvedata)
