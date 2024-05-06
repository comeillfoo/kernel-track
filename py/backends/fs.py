#!/usr/bin/env python3
import os
import json

from functools import reduce


class Database:
    name='fs'
    config_template='''BACKEND = 'fs'
PATH = '{path-to-database-folder}'

'''

    def __init__(self, config: dict):
        db_path = config.get('PATH', None)
        if db_path is None:
            raise Exception

        self.db = db_path
        self.tables = [
            'users.json',
            'projects.json',
            'vulnerabilities.json',
            'reports.json'
        ]


    def init(self):
        os.makedirs(self.db)
        for table_path in map(lambda table: os.path.join(self.db, table),
                              self.tables):
            with open(table_path, 'w') as fp:
                json.dump({}, fp)


    def ping(self) -> bool:
        return os.path.isdir(self.db) and reduce(lambda acc, table_path: acc and os.path.isfile(table_path),
                                                 map(lambda table: os.path.join(self.db, table),
                                                     self.tables), True)