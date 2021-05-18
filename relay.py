import base64
import json
import argparse
import asyncio
from json.decoder import JSONDecodeError
import rsa
from socket import *
import logging
import time
from cryptography.fernet import Fernet
import copy

logging.basicConfig(
    format='%(filename)s:%(lineno)s:%(levelname)s @ %(asctime)s > %(message)s', level=logging.DEBUG)


def ip():
    return gethostbyname(gethostname())


parser = argparse.ArgumentParser(description='Run SPEAR Relay Server')
parser.add_argument('--config', help='Path to config.json file. Required.')

args = parser.parse_args()
try:
    with open(args.config, 'r') as f:
        config = json.load(f)
except OSError:
    raise FileNotFoundError('Path to config file is invalid.')
except JSONDecodeError:
    raise ValueError('Badly formatted JSON config.')


class Relay:
    def __init__(self):
        self.networks = {}
        self.public, self.private = rsa.newkeys(512)
        self.relays = []


relay = Relay()


async def handle_relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    data = await reader.readline()
    message = data.decode('utf-8').strip('\n')
    if message == 'RSAREQUEST':
        logging.debug(f'RECV RSAREQUEST {writer.get_extra_info("peername")}')
        writer.write(base64.urlsafe_b64encode(relay.public.save_pkcs1())+b'\n')
        await writer.drain()
        writer.close()
        return
    else:
        try:
            key, data = message.split('§')
            fernet = Fernet(rsa.decrypt(base64.urlsafe_b64decode(
                key.encode('utf-8')), relay.private))
            data = fernet.decrypt(base64.urlsafe_b64decode(
                data.encode('utf-8'))).decode('utf-8')
        except rsa.DecryptionError:
            logging.exception('Error decrypting message: ')
            writer.write(b'error\n')
            await writer.drain()
            writer.close()
            return
        command, arguments = data.split(':', maxsplit=1)
        arguments = json.loads(arguments)
        if command == 'PING':
            if not arguments['network'] in relay.networks:
                relay.networks[arguments['network']] = {}
            if arguments['advertise']:
                if arguments['peer_id'] in relay.networks[arguments['network']].keys():
                    relay.networks[arguments['network']
                                ][arguments['peer_id']]['last_ping'] = time.time()
                else:
                    relay.networks[arguments['network']][arguments['peer_id']] = {
                        'id': arguments['peer_id'],
                        'name': arguments['peer_name'],
                        'network': arguments['network'],
                        'public_key': rsa.PublicKey.load_pkcs1(base64.urlsafe_b64decode(arguments['public_key'].encode('utf-8'))),
                        'last_ping': time.time(),
                        'buffer': []
                    }
                relay.relays.extend(arguments['relays'])
                relay.relays = list(set(relay.relays))
                return_packet = json.dumps({
                    'peers': {i: [relay.networks[arguments['network']][i]['name'], base64.urlsafe_b64encode(relay.networks[arguments['network']][i]['public_key'].save_pkcs1()).decode('utf-8')] for i in relay.networks[arguments['network']].keys()},
                    'relays': relay.relays,
                    'public_key': base64.urlsafe_b64encode(relay.public.save_pkcs1()).decode('utf-8'),
                    'buffer': copy.deepcopy(relay.networks[arguments['network']][arguments['peer_id']]['buffer'])
                })
                relay.networks[arguments['network']][arguments['peer_id']]['buffer'] = []
            else:
                relay.relays.extend(arguments['relays'])
                relay.relays = list(set(relay.relays))
                return_packet = json.dumps({
                    'peers': {i: [relay.networks[arguments['network']][i]['name'], base64.urlsafe_b64encode(relay.networks[arguments['network']][i]['public_key'].save_pkcs1()).decode('utf-8')] for i in relay.networks[arguments['network']].keys()},
                    'relays': relay.relays,
                    'public_key': base64.urlsafe_b64encode(relay.public.save_pkcs1()).decode('utf-8'),
                    'buffer': []
                })
        elif command == 'CMND':
            logging.debug(f'DATA: {arguments["network"]}.{arguments["originator"]} -> {arguments["network"]}.{arguments["target"]}')
            relay.networks[arguments['network']][arguments['target']]['buffer'].insert(0, {
                'id': arguments['id'],
                'originator': arguments['originator'],
                'data': arguments['data'],
                'type': 'cmd'
            })
            return_packet = '{}'
        elif command == 'RESP':
            logging.debug(f'DATA: {arguments["network"]}.{arguments["originator"]} -> {arguments["network"]}.{arguments["target"]}')
            relay.networks[arguments['network']][arguments['target']]['buffer'].insert(0, {
                'id': arguments['id'],
                'originator': arguments['originator'],
                'data': arguments['data'],
                'type': 'resp'
            })
            return_packet = '{}'
        
        dat = base64.urlsafe_b64encode(
            fernet.encrypt(return_packet.encode('utf-8')))+b'\n'
        writer.write(dat)
        await writer.drain()
        writer.close()
        return


async def run_relay():
    server = await asyncio.start_server(handle_relay, ip(), config['relay_port'])
    addr = server.sockets[0].getsockname()

    logging.info(f'Started SPEAR Relay on {addr}.')

    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(run_relay())
