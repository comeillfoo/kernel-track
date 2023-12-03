#!/usr/bin/env python3
from typing import Tuple


class LxKernelCVE:
    @classmethod
    def parse_affected_versions(cls, affected_versions: str) -> Tuple[str, str]:
        return ''


    def __init__(self, cveid: str, cvedata: dict):
        self.id = cveid
        self.affected_versions = LxKernelCVE.parse_affected_versions(cvedata.get('affected_versions', 'unk to unk'))

        # hash commits
        self.breaks = cvedata.get('breaks', '')
        self.fixes = cvedata.get('fixes', '')

        self.last_modified = cvedata.get('last_modified', '')
        self.nvd_text = cvedata.get('nvd_text', '')


    db = {}
    @classmethod
    def __getitem__(cls, cveid: str):
        return cls.db.get(cveid, None)

    @classmethod
    def __setitem__(cls, cveid: str, cvedata: dict):
        cls.db[cveid] = LxKernelCVE(cveid, cvedata)
