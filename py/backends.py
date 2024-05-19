#!/usr/bin/env python3
import importlib.util
import sys
import os
import pathlib

from typing import Tuple, Optional
from types import ModuleType


SUPPORTED_BACKENDS=[]
BACKENDS_DIR='backends'


def _specs(parent: str, file: str) -> Tuple[str, str]:
    return ('.'.join([parent, file.rstrip('.py')]),
            os.path.join(parent, file))


for backend_file in os.listdir(BACKENDS_DIR):
    if not backend_file.endswith('py'):
        # print(f'Ignore \'{backend_file}\' is not a python-module')
        continue
    try:
        modname, modpath = _specs(BACKENDS_DIR, backend_file)
        spec = importlib.util.spec_from_file_location(modname, modpath)
        backend_inst = importlib.util.module_from_spec(spec)
        sys.modules[modname] = backend_inst
        spec.loader.exec_module(backend_inst)

        SUPPORTED_BACKENDS.append(backend_inst.Database.name)
    except Exception as e:
        print(f'Failed to load backend \'{backend_file}\'', e)


DEFAULT_CONFIG_PATH = pathlib.Path('./config.toml')

def get_backend(backend: Optional[str]) -> ModuleType:
    if backend is None or backend not in SUPPORTED_BACKENDS:
        print(f'Invalid backend: {backend} not supported')
        raise Exception
    backend_inst = sys.modules.get('.'.join([ 'backends', backend ]), None)
    if backend_inst is None:
        print(f'Failed to get backend {backend}')
        raise Exception
    return backend_inst
