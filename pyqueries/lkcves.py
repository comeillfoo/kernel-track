#!/usr/bin/env python3
import requests
import json
import pprint


kernel_cves_url = 'https://raw.githubusercontent.com/nluedtke/linux_kernel_cves/master/data/kernel_cves.json'


def main() -> int:
    kernel_cves = json.loads(requests.get(kernel_cves_url).text) # TODO errors handling
    pprint.pprint(kernel_cves)
    return 0


if __name__ == '__main__':
    exit(main())
