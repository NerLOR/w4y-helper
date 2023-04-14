#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
from typing import Optional, List, Tuple, Dict
import argparse
import datetime
import time
import configparser
import requests
import hashlib
import json
import re
import hmac
from email.mime.text import MIMEText
import smtplib

import World4YouApi.src.World4YouApi as World4YouApi


CACHE_FILE = 'last-addr.txt'
HTTP_TIMEOUT: int = 600
SLEEP: int = 60
SLEEP_SHORT: int = 5

LAST_ADDRESSES: List[Tuple[Optional[str], Optional[str]]] = []
CURR_ADDRESSES: List[Tuple[Optional[str], Optional[str]]] = []
DNS_CONFIG: List[DnsConfig]
ADDRESS_SOURCES: List[AddressSource]

EMAIL_FROM: str
EMAIL_TO: str
EMAIL_TRY_SEC: int
EMAIL_TRY_TIMES: int
EMAIL_TRY_INTERVAL: int
SMTP_HOST: str
SMTP_PORT: int
SMTP_USER: str
SMTP_PASSWORD: str


class DnsConfig:
    user: int
    password: str
    records_v4: List[str]
    records_v6: Dict[str, str]

    def __init__(self, user: int, password: str, v4: List[str], v6: Dict[str, str]):
        self.user = user
        self.password = password
        self.records_v4 = v4
        self.records_v6 = v6

    def __str__(self) -> str:
        return f'{{{self.user}}}'


class AddressSource:
    name: str
    type: str
    hostname: str
    user: str
    password: str

    def __init__(self, name: str, t: str):
        self.name = name
        self.type = t

    def __str__(self) -> str:
        return f'{{{self.name}, {self.type}}}'


class Status:
    ipv4_address: Optional[str]
    ipv6_prefix: Optional[str]
    up: bool

    def __init__(self, v4: str = None, v6: str = None, up: bool = False):
        self.ipv4_address = v4
        self.ipv6_prefix = v6
        self.up = up

    def __repr__(self) -> str:
        return f'{{{"UP" if self.up else "DOWN"}, {self.ipv4_address}, {self.ipv6_prefix}}}'

    def __str__(self) -> str:
        return self.__repr__()


def get_value(string: str) -> Optional[str]:
    string = string.strip()
    if string in ('', 'None'):
        return None
    return string


def cut(base: str, start: str, end: str) -> Optional[str]:
    pos1 = base.find(start)
    if pos1 < 0:
        return None
    pos2 = base.find(end, pos1 + len(start) + 1)
    if pos2 < 0:
        return None
    return base[pos1 + len(start):pos2]


def html_clean(string: str) -> str:
    return re.sub(r'\s+', ' ', re.sub(r'<[^>]*>', ' ', string)).strip()


def build_ipv6_address(prefix: str, fmt: str):
    prefix = prefix.split('/')[0].strip(':')
    return fmt.format(prefix=prefix)


def read_cache() -> None:
    global LAST_ADDRESSES

    print(f'Reading {CACHE_FILE}', flush=True)
    try:
        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        return
    if len(lines) // 2 != len(LAST_ADDRESSES):
        return

    for i in range(0, len(lines), 2):
        LAST_ADDRESSES[i // 2] = (get_value(lines[i]), get_value(lines[i + 1]))


def update_cache() -> None:
    print(f'Updating {CACHE_FILE}', flush=True)
    with open(CACHE_FILE, 'w+', encoding='utf-8') as f:
        for addr in LAST_ADDRESSES:
            f.write(f'{addr[0]}\n{addr[1]}\n')


def send_email() -> None:
    print('Sending email', flush=True)
    text = ''
    for i, source in enumerate(ADDRESS_SOURCES):
        curr_addr = CURR_ADDRESSES[i]
        last_addr = LAST_ADDRESSES[i]
        text += f'{source.name}:\n\n' \
                f'IPv4 old: {str(last_addr[0]):>15}\n' \
                f'IPv4 new: {str(curr_addr[0]):>15}\n\n' \
                f'IPv6 old: {str(last_addr[1]):>22}\n' \
                f'IPv6 new: {str(curr_addr[1]):>22}\n\n' \
                f'================================================\n\n'

    msg = MIMEText(text, 'plain', 'UTF-8')
    msg['From'] = EMAIL_FROM
    msg['To'] = EMAIL_TO
    msg['Date'] = datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')
    msg['Subject'] = 'Public IP address updated'

    for i in range(EMAIL_TRY_TIMES):
        try:
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
            server.quit()
            break
        except Exception as e:
            if i >= EMAIL_TRY_TIMES - 1:
                raise e
        time.sleep(EMAIL_TRY_INTERVAL)


def update_dns_records(v4_addr: str, v6_prefix: str) -> None:
    print('Updating DNS records', flush=True)
    for dns in DNS_CONFIG:
        print('Logging in...', flush=True)
        api = World4YouApi.MyWorld4You()
        if api.login(dns.user, dns.password):
            print('Successfully logged in', flush=True)
        else:
            print('Unable to log in', flush=True)
            exit(1)

        rrs = {}
        for rr in dns.records_v4:
            rrs[(rr, 'A')] = api.get_resource_record(rr, 'A')
            print(f'{rr:24} - {rrs[(rr, "A")].value}', flush=True)
        for rr in dns.records_v6.keys():
            rrs[(rr, 'AAAA')] = api.get_resource_record(rr, 'AAAA')
            print(f'{rr:24} - {rrs[(rr, "AAAA")].value}', flush=True)

        for rr in dns.records_v4:
            if rrs[(rr, 'A')].value != v4_addr:
                print(f'Updating {rr} (A)', flush=True)
                api.update_resource_record(rrs[(rr, 'A')], new_value=v4_addr)
        for rr, fmt in dns.records_v6.items():
            v6_addr = build_ipv6_address(v6_prefix, fmt)
            if rrs[(rr, 'AAAA')].value != v6_addr:
                print(f'Updating {rr} (AAAA)', flush=True)
                api.update_resource_record(rrs[(rr, 'AAAA')], new_value=v6_addr)


def read_config(filename: str) -> None:
    global DNS_CONFIG, ADDRESS_SOURCES, SLEEP, SLEEP_SHORT, HTTP_TIMEOUT, \
        EMAIL_FROM, EMAIL_TO, EMAIL_TRY_SEC, EMAIL_TRY_TIMES, EMAIL_TRY_INTERVAL, \
        SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD

    config = configparser.ConfigParser()
    if len(config.read(filename)) == 0:
        raise FileNotFoundError(f'config file \'{filename}\' not found')

    SLEEP = int(config['general']['sleep'])
    SLEEP_SHORT = int(config['general']['sleep_short'])
    HTTP_TIMEOUT = int(config['http']['timeout'])

    EMAIL_FROM = config['email']['sender']
    EMAIL_TO = config['email']['recipient']
    EMAIL_TRY_SEC = int(config['email']['try_sec'])
    EMAIL_TRY_INTERVAL = int(config['email']['try_interval'])
    EMAIL_TRY_TIMES = EMAIL_TRY_SEC // EMAIL_TRY_INTERVAL + 1

    SMTP_HOST = config['email']['smtp_host']
    SMTP_PORT = int(config['email']['smtp_port'])
    SMTP_USER = config['email']['smtp_user']
    SMTP_PASSWORD = config['email']['smtp_password']

    ADDRESS_SOURCES = []
    for sec_name in [s for s in config.sections() if s.startswith('source.')]:
        sec = config[sec_name]
        if not sec.getboolean('active', fallback=True):
            continue
        source = AddressSource(sec['name'], sec['type'])
        if source.type in ('fritzbox', 'a1'):
            source.hostname = sec['hostname']
            source.user = sec['user']
            source.password = sec['password']
        ADDRESS_SOURCES.append(source)

    DNS_CONFIG = []
    for sec_name in [s for s in config.sections() if s.startswith('dns.')]:
        sec = config[sec_name]
        v4 = [a.strip() for a in sec.get('records_v4', '').split(',') if len(a.strip()) > 0]
        v6 = {p.strip().split(' ')[0]: p.strip().split(' ')[-1]
              for p in sec.get('records_v6', '').split(',') if len(p.strip()) > 0}
        DNS_CONFIG.append(DnsConfig(int(sec['user']), sec['password'], v4, v6))


def status_fritzbox(source: AddressSource) -> Status:
    stat = Status()
    url = f'http://{source.hostname}'
    s = requests.session()

    try:
        r = s.get(f'{url}/login_sid.lua?version=2', timeout=HTTP_TIMEOUT)
    except:
        return stat

    challenge = cut(r.text, '<Challenge>', '</Challenge>')
    if challenge is None:
        return stat

    n, iter1, salt1, iter2, salt2 = challenge.split('$')

    hash1 = hashlib.pbkdf2_hmac('sha256', source.password.encode('utf8'), bytes.fromhex(salt1), int(iter1))
    hash2 = hashlib.pbkdf2_hmac('sha256', hash1, bytes.fromhex(salt2), int(iter2))
    response = f'{salt2}${hash2.hex()}'

    r = s.post(f'{url}/login_sid.lua?version=2', {
        'username': source.user,
        'response': response,
    }, timeout=HTTP_TIMEOUT)
    sid = cut(r.text, '<SID>', '</SID>')
    if sid is None or len(sid) == sid.count('0'):
        raise RuntimeError('Invalid password')

    r = s.post(f'{url}/data.lua', {
        'sid': sid,
        'page': 'netMoni',
        'xhrId': 'all',
        'xhr': 1,
    }, timeout=HTTP_TIMEOUT)

    data = json.loads(r.text)
    cnx = data['data']['connections'][0]
    stat.up = cnx['connected'] and cnx['active']

    address = cnx['ipv4']['ip']
    if address is not None:
        stat.ipv4_address = address

    prefix = cnx['ipv6']['prefix']
    if prefix is not None:
        stat.ipv6_prefix = prefix.split(',')[0]

    return stat


def status_a1(source: AddressSource) -> Status:
    stat = Status()
    url = f'http://{source.hostname}'
    s = requests.session()

    try:
        r = s.get(f'{url}/ui/login', timeout=HTTP_TIMEOUT)
        nonce = cut(r.text, 'name="nonce" value="', '"')
        code1 = cut(r.text, "name='code1' value='", "'")
        code3 = cut(r.text, "name='code3' value='", "'")
        pw = hmac.new(nonce.encode('utf8'),
                      msg=source.password.encode('utf8'),
                      digestmod=hashlib.sha256).hexdigest().lower()

        r = s.post(f'{url}/ui/login', {
            'userName': source.user,
            'language': 'DE',
            'userPwd': pw,
            'login': 'Login',
            'code1': code1,
            'code3': code3,
            'nonce': nonce,
        }, timeout=HTTP_TIMEOUT)
        text = r.text
    except:
        return stat

    connection_str = cut(text, "<label class='title'>Internet Verbindung:</label>", '</div>')
    stat.up = (connection_str is not None and html_clean(connection_str).lower() == 'up' or False)

    address_str = cut(text, '<label>IP Adresse:</label>', '</div>')
    address = html_clean(address_str) if address_str is not None else None
    if address is not None and address != 'Nicht Belegt':
        address = [a for a in filter(lambda a: ':' not in a, address.split(' '))]
        stat.ipv4_address = address[0] if len(address) > 0 else None

    prefix_str = cut(text, '<label>IPv6 Prefixes:</label>', '</div>')
    prefix = html_clean(prefix_str) if prefix_str is not None else None
    if prefix is not None and prefix != 'Nicht Belegt':
        stat.ipv6_prefix = prefix

    return stat


def get_addresses() -> bool:
    global CURR_ADDRESSES
    statuses = []
    for i, source in enumerate(ADDRESS_SOURCES):
        status = Status()
        print(f'Getting address fo {source.name} ({source.type})', flush=True)
        if source.type == 'fritzbox':
            status = status_fritzbox(source)
        elif source.type == 'a1':
            status = status_a1(source)
        print(f'Status: {status}', flush=True)
        statuses.append(status)
    CURR_ADDRESSES = [(s.ipv4_address, s.ipv6_prefix) for s in statuses]
    return all([s.up for s in statuses])


def main() -> None:
    global LAST_ADDRESSES, CURR_ADDRESSES

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', type=str, default='config.ini',
                        help='The config file to use')
    args = parser.parse_args()

    read_config(args.config)
    LAST_ADDRESSES = [(None, None)] * len(ADDRESS_SOURCES)
    CURR_ADDRESSES = [(None, None)] * len(ADDRESS_SOURCES)

    print('Starting', flush=True)
    read_cache()
    while True:
        if not get_addresses():
            print(f'Waiting for valid ip addresses ({SLEEP_SHORT} sec)', flush=True)
            time.sleep(SLEEP_SHORT)
            continue
        elif LAST_ADDRESSES == CURR_ADDRESSES:
            print(f'Nothing to do ({SLEEP} sec)', flush=True)
            time.sleep(SLEEP)
            continue

        send_email()
        update_dns_records(CURR_ADDRESSES[0][0], CURR_ADDRESSES[0][1])
        LAST_ADDRESSES = CURR_ADDRESSES
        update_cache()
        print('Finished', flush=True)


if __name__ == '__main__':
    main()
