#!/usr/bin/env python3
import os
import json
import base64 as b64

from typing import Optional

from functools import reduce


def _encrypt(string: str) -> str:
    return b64.b64encode(str.encode(string, encoding='utf-8')) \
        .decode(encoding='utf-8')


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
        self.tables = {
            'users': 'users.json',
            'systems': 'systems.json',
            'vulnerabilities': 'vulnerabilities.json',
            'reports': 'reports.json'
        }


    def _load_table(self, table: str) -> dict:
        with open(os.path.join(self.db, self.tables[table]), 'r') as fp:
            return json.load(fp)


    def _dump_table(self, table: str, table_obj: dict) -> bool:
        with open(os.path.join(self.db, self.tables[table]), 'w') as fp:
            json.dump(table_obj, fp)
        return True


    def update_entry(self, table: str, row: str, value: dict) -> bool:
        table_obj = self._load_table(table)
        table_obj[row] = value
        return self._dump_table(table, table_obj)


    def select_entry(self, table: str, row: str) -> Optional[dict]:
        return self._load_table(table).get(row, None)


    def delete_entry(self, table: str, row: str) -> bool:
        table_obj = self._load_table(table)
        table_obj.pop(row, None)
        return self._dump_table(table, table_obj)

    def init(self):
        os.makedirs(self.db)
        for _, tfile in self.tables.items():
            tpath = os.path.join(self.db, tfile)
            with open(tpath, 'w') as fp:
                json.dump({}, fp)

        # create default user
        self.update_entry('users', 'admin', {
            'role': 'admin',
            'pwd': _encrypt('admin')
        })
        print('created default admin user admin:admin, '
              'consider taking appropriate changes')


    def ping(self) -> bool:
        return os.path.isdir(self.db) and reduce(lambda acc, table_path: acc and os.path.isfile(table_path),
                                                 map(lambda table: os.path.join(self.db, table),
                                                     self.tables), True)


    def authenticate(self, user: str, password: str) -> bool:
        user = self.select_entry('users', user)
        if user is None:
            return False
        return b64.b64encode(str.encode(password, encoding='utf-8')) \
            .decode(encoding='utf-8') == user['pwd']


    def authorize(self, user: str) -> bool:
        user = self.select_entry('users', user)
        if user is None:
            return False
        return user['role'] == 'admin'


    def add_user(self, login: str, password: str, role: str) -> bool:
        if self.select_entry('users', login) is not None:
            return False

        return self.update_entry('users', login, {
            'role': role,
            'pwd': self._encrypt(password),
        })


    def delete_user(self, login: str) -> bool:
        return self.delete_entry('users', login)
