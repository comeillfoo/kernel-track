#!/usr/bin/env python3
import sqlite3
import base64 as b64


def _encrypt(string: str) -> str:
    return b64.b64encode(str.encode(string, encoding='utf-8')) \
        .decode(encoding='utf-8')


class Database:
    name='sqlite'
    config_template='''BACKEND = 'sqlite'
PATH = '{path-to-database-file}'

'''

    def __init__(self, config: dict):
        db_path = config.get('PATH', None)
        if db_path is None:
            raise Exception

        self.db = db_path

    def init(self):
        conn = sqlite3.connect(self.db)
        cursor = conn.cursor()

        # create tables
        cursor.executescript('''
create table roles(
    id text primary key
);

insert into roles(id) values ('admin'), ('inspector');

create table users(
    name text primary key,
    role text,
    password text,
    foreign key(role) references roles(id)
);

insert into users(name, role, password) values ('admin', 'admin', '%s');

create table systems(
    title text primary key
);

create table sources(
    id text primary key
);

insert into sources(id) values ('manual');

create table vulnerabilities(
    id text primary key,
    source text,
    foreign key(source) references sources(id)
);

create table reports(
    id integer primary key,
    owner text,
    foreign key(owner) references users(name)
);

create table reports_references(
    flaw integer,
    report integer,
    primary key(flaw, report),
    foreign key(flaw) references vulnerabilities(name),
    foreign key(report) references reports(id)
);
''' % (_encrypt('admin')))
        print('created default admin user admin:admin, '
              'consider taking appropriate changes')
        conn.close()

    def ping(self) -> bool:
        core_tables = { 'users', 'reports', 'vulnerabilities', 'systems' }

        conn = sqlite3.connect(self.db)
        cursor = conn.cursor()
        cursor.execute('select name from sqlite_master where type=\'table\'')
        existed_tables = set(list(sum(cursor.fetchall(), ())))
        conn.close()
        return (core_tables & existed_tables) == core_tables
