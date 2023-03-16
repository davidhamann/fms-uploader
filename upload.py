import logging
import time
import sys
import base64
from pathlib import Path

import requests
from Cryptodome.Cipher import PKCS1_v1_5
from Cryptodome.PublicKey import RSA

PROXIES = {}


def encrypt(plaintext, pub_key):
    key = RSA.import_key(pub_key)
    cipher = PKCS1_v1_5.new(key)
    return cipher.encrypt(plaintext)


def get_pub_key(host):
    res = request(f'https://{host}/fmws/serverInfo')
    return res.json()['data']['PublicKey']


def get_session_token(host, username, password):
    logging.info('Getting RSA public key')
    pub_key = get_pub_key(host)

    encrypted_username = encrypt(bytes(username, encoding='utf-8'), pub_key)
    encrypted_password = encrypt(bytes(password, encoding='utf-8'), pub_key)

    encoded_username = base64.b64encode(encrypted_username).decode()
    encoded_password = base64.b64encode(encrypted_password).decode()

    headers = {
        'X-FMS-Command': 'authentication',
        'X-FMS-Encrypted-Username': encoded_username,
        'X-FMS-Encrypted-Password': encoded_password,
        'X-FMS-Authentication-Type': '1',
        'X-FMS-Application-Version': '19'
    }

    logging.info('Getting session token')
    res = request(f'https://{host}/fmws', headers=headers)

    return res.json()['data']['sessionKey']


def request(url, method='GET', **kwargs):
    return requests.request(url=url, method=method, verify='root.pem',
                            proxies=PROXIES, **kwargs)


def send_upload_event(host, session_token, event, filename):
    headers = {
        'X-FMS-Command': 'databaseuploadevent',
        'X-FMS-Session-Key': session_token,
        'X-FMS-Upload-Event': event
    }
    res = request(f'https://{host}/fmws/MainDB/{filename}', headers=headers)

    return res.headers['X-FMS-Result']


def upload_file(host, session_token, file_path):
    filename = file_path.name
    headers = {
        'X-FMS-Command': 'upload',
        'X-FMS-Session-Key': session_token,
        'X-FMS-Append-Checksum': 'false',
        'Content-Type': 'application/octet-stream',
        'Expect': '100-continue'  # hack (requests not supporting 100-Continue)
    }
    with open(file_path, 'rb') as f:
        res = request(f'https://{host}/fmws/MainDB/UploadTemp_FMS'
                      f'/{session_token}/{filename}', headers=headers,
                      method='PUT', data=f)

    return res.headers['X-FMS-Result']


def open_database(host, session_token, filename):
    headers = {
        'X-FMS-Command': 'dboperation',
        'X-FMS-Session-Key': session_token,
        'X-FMS-DBOperation': 'open',
        'X-FMS-Force': '0'
    }

    res = request(f'https://{host}/fmws/MainDB/{filename}', headers=headers)

    return res.headers['X-FMS-Result']


def get_db_status(host, session_token, filename):
    headers = {
        'X-FMS-Command': 'dbstatus',
        'X-FMS-Session-Key': session_token
    }

    res = request(f'https://{host}/fmws/MainDB/{filename}', headers=headers)

    return res.json()['data']['fileStatus']


def main(host, username, password, file_):
    session_token = get_session_token(host, username, password)
    logging.info(f'Got session token: {session_token}')

    file_path = Path(file_)
    filename = file_path.name

    logging.info('Sending upload start event')
    start_event = send_upload_event(host, session_token, '1', filename)
    if start_event != '0':
        logging.error('Start event failed. Result: {start_event}')
        return

    logging.info('Uploading file')
    upload = upload_file(host, session_token, file_path)
    if upload != '0':
        logging.error('Upload failed. Result: {upload}')
        return
    logging.info('Upload done')

    logging.info('Sending upload end event')
    end_event = send_upload_event(host, session_token, '2', filename)
    if end_event != '0':
        logging.error('End event failed. Result: {end_event}')
        return

    logging.info('Sending open database command')
    open_db = open_database(host, session_token, filename)
    if open_db != '0':
        logging.error('Open DB command failed. Result: {open_db}')
        return

    tries = 0
    while tries < 10:
        logging.info('Checking status')
        tries += 1
        status = get_db_status(host, session_token, filename)
        if status == 2:
            logging.info('DB open')
            break
        time.sleep(1)
    else:
        logging.info(f'DB not open (status: {status})')

    logging.info('Done')


if __name__ == '__main__':
    logging.basicConfig(format='%(levelname)s:%(message)s',
                        level=logging.INFO)

    argc = len(sys.argv)
    if argc < 5:
        print(f'Usage: python3 {sys.argv[0]} <host> <username> <password> <file>')
    else:
        main(*sys.argv[1:5])
