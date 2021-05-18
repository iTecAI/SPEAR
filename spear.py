from asyncio.streams import StreamWriter
from socket import *
import asyncio
from cryptography.fernet import Fernet, InvalidToken
import rsa
import hashlib
import random
import time
import functools
import threading
import base64
import json
from concurrent.futures import ThreadPoolExecutor
import pickle
import traceback
import inspect

def check_port(port):
    c_sock = socket(AF_INET, SOCK_STREAM)
    res = c_sock.connect_ex(('127.0.0.1', port)) == 0
    c_sock.close()
    return res


def free_port():
    free_socket = socket(AF_INET, SOCK_STREAM)
    free_socket.bind(('0.0.0.0', 0))
    free_socket.listen(5)
    port = free_socket.getsockname()[1]
    free_socket.close()
    return port


def ip():
    return gethostbyname(gethostname())


class Peer:
    def __init__(self, originator, target='*', thread_count=None, timeout=1e99):
        self.originator = originator
        if target == '*':
            self.peers = {}
            for p in originator.peers['local'].keys():
                self.peers[p] = originator.peers['local'][p]
            for p in originator.peers['remote'].keys():
                if not p in self.peers.keys():
                    self.peers[p] = originator.peers['remote'][p]
        elif type(target) == list:
            self.peers = {x['id']: x for x in [
                originator.find_peer(i) for i in target]}
        else:
            self.peers = {}
            peer = originator.find_peer(target)
            self.peers[peer['id']] = peer
        self.thread_count = thread_count
        self.timeout = timeout

    def command_one(self, target, path, args=[], kwargs={}):
        try:
            peer = self.peers[target]
            temp_key = Fernet.generate_key()
            if peer['type'] == 'local':
                packet_raw = {
                    'originator': self.originator.id,
                    'originator_name': self.originator.name,
                    'originator_key': base64.urlsafe_b64encode(self.originator.public.save_pkcs1()).decode('utf-8'),
                    'originator_type': 'local',
                    'originator_ip': [ip(), self.originator.service_port],
                    'target': target,
                    'path': path,
                    'args': [base64.urlsafe_b64encode(pickle.dumps(arg)).decode('utf-8') for arg in args],
                    'kwargs': {key: base64.urlsafe_b64encode(pickle.dumps(kwargs[key])).decode('utf-8') for key in kwargs.keys()}
                }
                encoded_packet = base64.urlsafe_b64encode(
                    json.dumps(packet_raw).encode('utf-8'))
                encrypted_packet = base64.urlsafe_b64encode(
                    Fernet(temp_key).encrypt(encoded_packet))
                encrypted_key = base64.urlsafe_b64encode(
                    rsa.encrypt(temp_key, peer['public_key']))
                assembled_packet = encrypted_key + \
                    '§'.encode('utf-8') + encrypted_packet
                if self.originator.network_encryption:
                    assembled_packet = base64.urlsafe_b64encode(
                        self.originator.network_encryption.encrypt(assembled_packet))

                temp_socket = create_connection(
                    (peer['address'].split(':')[0], int(peer['address'].split(':')[1])))
                temp_socket.sendall(assembled_packet+b'\n')
                response = b''
                start = time.time()
                while True and time.time() < start + self.timeout:
                    data = temp_socket.recv(1024)
                    if len(data) == 0:
                        break
                    response += data.strip(b'\n')
                if time.time() >= start + self.timeout:
                    raise TimeoutError
                
                if self.originator.network_encryption:
                    response = self.originator.network_encryption.decrypt(base64.urlsafe_b64decode(response))
                response = base64.urlsafe_b64decode(response)
                response = Fernet(temp_key).decrypt(response)
                response = base64.urlsafe_b64decode(response).decode('utf-8')
                response = json.loads(response)
                return response

            else:
                relay = random.choice(peer['relays'])
                if ':' in relay:
                    relay = [relay.split(':')[0], int(relay.split(':')[1])]
                else:
                    relay = [relay, 2201]
                relay_str = relay[0] + ':' + str(relay[1])
                packet_raw = {
                    'type': 'command',
                    'originator': self.originator.id,
                    'originator_name': self.originator.name,
                    'originator_key': base64.urlsafe_b64encode(self.originator.public.save_pkcs1()).decode('utf-8'),
                    'originator_type': 'remote',
                    'originator_relay': relay,
                    'target': target,
                    'path': path,
                    'args': [base64.urlsafe_b64encode(pickle.dumps(arg)).decode('utf-8') for arg in args],
                    'kwargs': {key: base64.urlsafe_b64encode(pickle.dumps(kwargs[key])).decode('utf-8') for key in kwargs.keys()}
                }
                encoded_packet = base64.urlsafe_b64encode(
                    json.dumps(packet_raw).encode('utf-8'))
                encrypted_packet = base64.urlsafe_b64encode(
                    Fernet(temp_key).encrypt(encoded_packet))
                encrypted_key = base64.urlsafe_b64encode(
                    rsa.encrypt(temp_key, peer['public_key']))
                assembled_packet = encrypted_key + \
                    '§'.encode('utf-8') + encrypted_packet
                if self.originator.network_encryption:
                    assembled_packet = base64.urlsafe_b64encode(
                        self.originator.network_encryption.encrypt(assembled_packet))
                
                block_id = hashlib.sha256(str(time.time() + random.uniform(-1,1)).encode('utf-8')).hexdigest()
                
                try:
                    sock = create_connection(relay, timeout=2)
                except TimeoutError:
                    self.originator.relays[relay_str]['public_key'] = None
                    return
                packet = json.dumps({
                    'originator': self.originator.id,
                    'target': target,
                    'network': self.originator.network_name,
                    'id': block_id,
                    'data': assembled_packet.decode('utf-8')
                })
                packet = 'CMND:' + packet
                tfk = Fernet.generate_key()
                tempfernet = Fernet(tfk)
                enc = rsa.encrypt(tfk, self.originator.relays[relay_str]['public_key'])
                to_send = base64.urlsafe_b64encode(
                    enc)+'§'.encode('utf-8')+base64.urlsafe_b64encode(tempfernet.encrypt(packet.encode('utf-8')))+b'\n'
                sock.sendall(to_send)
                packet_response = ''
                while True:
                    dat = sock.recv(1024)
                    if not dat:
                        break
                    packet_response += dat.decode('utf-8').strip()
                sock.close()
                if packet_response == 'error':
                    self.originator.relays[relay_str]['public_key'] = None
                    return 'error'
                decrypted = tempfernet.decrypt(
                    base64.urlsafe_b64decode(packet_response.encode('utf-8')))
                if decrypted == 'error':
                    print('Encryption error')
                
                start = time.time()
                while True and time.time() < start + self.timeout:
                    if block_id in self.originator.responses.keys():
                        break
                if time.time() >= start + self.timeout:
                    raise TimeoutError
                
                response = self.originator.responses[block_id]['data'].encode('utf-8')
                if self.originator.network_encryption:
                    response = self.originator.network_encryption.decrypt(base64.urlsafe_b64decode(response))
                response = base64.urlsafe_b64decode(response)
                response = Fernet(temp_key).decrypt(response)
                response = base64.urlsafe_b64decode(response).decode('utf-8')
                response = json.loads(response)
                del self.originator.responses[block_id]
                return response

        except:
            traceback.print_exc()

    def command(self, path, *args, **kwargs):
        with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
            results = {pid: executor.submit(
                self.command_one, pid, path, args=args, kwargs=kwargs) for pid in self.peers.keys()}
        finals = {r: results[r].result() for r in results.keys()}
        for f in finals.keys():
            if finals[f]['result_status'] == 200:
                finals[f] = pickle.loads(base64.urlsafe_b64decode(finals[f]['result'].encode('utf-8')))
            else:
                finals[f] = {
                    'result': 'ERROR',
                    'status': finals[f]['result_status'],
                    'reason': finals[f]['result']
                }
        if len(finals.keys()) == 1:
            return finals[list(finals.keys())[0]]
        else:
            return finals


class PeerNotFoundError(KeyError):
    pass

class SpearResponse:
    def __init__(self, status, data):
        self.status = status
        self.data = data


class Spear:  # Base Peer class
    def __init__(
        self,
        network_name,
        peer_name,
        relays=[],
        network_encryption=None,
        advertising_port=2200,
        port_range=(2300, 23000),
        use_remote=True,
        use_local=True,
        advertise=True
    ):
        self.network_name = network_name
        self.name = peer_name
        for i in range(len(relays)):
            if not ':' in relays[i]:
                relays[i] = relays[i] + ':2201'
        self.relays = {i: {
            'last_reply': time.time(),
            'public_key': None
        } for i in relays}
        self.ad_port = advertising_port
        self.id = hashlib.sha256(
            str(time.time() + random.uniform(-1, 1)).encode('utf-8')).hexdigest()
        while True:
            p = random.randint(*port_range)
            if not check_port(p):
                self.service_port = p
                break
        if network_encryption == None:
            self.network_encryption = False
        else:
            if type(network_encryption) == str:
                self.network_encryption = Fernet(
                    network_encryption.encode('utf-8'))
            else:
                self.network_encryption = Fernet(network_encryption)
        self.endpoints = {}
        self.sockets = {}
        (self.public, self.private) = rsa.newkeys(512)
        self.running = False
        self.peers = {
            'local': {},
            'remote': {}
        }
        self.threads = {}
        self.responses = {}

        self.use_local = use_local
        self.use_remote = use_remote
        self.advertise = advertise

    def find_peer(self, peer_name_or_id):
        if peer_name_or_id in self.peers['local'].keys():
            return self.peers['local'][peer_name_or_id]
        elif peer_name_or_id in self.peers['remote'].keys():
            return self.peers['remote'][peer_name_or_id]
        for p in self.peers['local'].values():
            if p['name'] == peer_name_or_id:
                return p
        for p in self.peers['remote'].values():
            if p['name'] == peer_name_or_id:
                return p
        raise PeerNotFoundError(
            f'Peer with name/ID "{peer_name_or_id}" not found.')

    def target(self, path):  # Function decorator to specify commands
        def dec_target(func):
            self.endpoints[path] = func

            @functools.wraps(func)
            def wrapper_target(*args, **kwargs):
                return func(*args, **kwargs)
            return wrapper_target
        return dec_target

    def run_advertiser(self):  # Local UDP advertiser thread
        self.sockets['advertiser'] = socket(AF_INET, SOCK_DGRAM)
        self.sockets['advertiser'].setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.sockets['advertiser'].bind(('', 0))
        self.sockets['advertiser'].setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        while self.running:
            raw_packet = '§'.join([str(i) for i in [
                self.network_name,
                self.id,
                self.name,
                ip() + ':' + str(self.service_port),
                base64.urlsafe_b64encode(
                    self.public.save_pkcs1()).decode('utf-8'),
                ','.join(self.relays)
            ]])
            if self.network_encryption:
                finished_packet = ('e§'+base64.urlsafe_b64encode(self.network_encryption.encrypt(
                    raw_packet.encode('utf-8'))).decode('utf-8')+'\n').encode('utf-8')
            else:
                finished_packet = ('d§'+raw_packet+'\n').encode('utf-8')
            self.sockets['advertiser'].sendto(
                finished_packet,
                (
                    '<broadcast>',
                    self.ad_port
                )
            )
            time.sleep(1)
        self.sockets['advertiser'].close()

    def discover_local_loop(self):  # Local discovery thread
        s = socket(AF_INET, SOCK_DGRAM)
        s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        s.bind(('', self.ad_port))
        while self.running:
            data, addr = s.recvfrom(1024)
            data = data.decode('utf-8')
            if not data.endswith('\n'):
                continue
            if data.startswith('e§'):
                try:
                    proc_packet = self.network_encryption.decrypt(base64.urlsafe_b64decode(
                        data.split('e§')[1].strip('\n').encode('utf-8'))).decode('utf-8').split('§')
                except InvalidToken:
                    continue
            else:
                proc_packet = data.split('§', maxsplit=1)[1].strip().split('§')

            for i in proc_packet[5].split(','):
                if not i in self.relays.keys():
                    if ':' in i:
                        r_ip = i
                    else:
                        r_ip = i + ':2201'
                    self.relays[r_ip] = {
                        'last_reply': time.time(),
                        'public_key': None
                    }

            if proc_packet[1] == self.id or proc_packet[0] != self.network_name:
                continue

            proc_packet = {
                'id': proc_packet[1],
                'name': proc_packet[2],
                'network': proc_packet[0],
                'address': proc_packet[3],
                'public_key': rsa.PublicKey.load_pkcs1(base64.urlsafe_b64decode(proc_packet[4].encode('utf-8'))),
                'ping_time': time.time(),
                'type': 'local'
            }

            self.peers['local'][proc_packet['id']] = proc_packet.copy()

    def check_peer_timeouts(self):  # Peer timeout thread
        while self.running:
            for k in list(self.peers['local'].keys()):
                if self.peers['local'][k]['ping_time'] + 2 < time.time():
                    del self.peers['local'][k]
            for k in list(self.peers['remote'].keys()):
                for r in self.peers['remote'][k]['relays'][:]:
                    if self.relays[r]['last_reply'] + 2 < time.time():
                        self.peers['remote'][k]['relays'].remove(r)
                if len(self.peers['remote'][k]['relays']) == 0:
                    del self.peers['remote'][k]
            time.sleep(1)

    def process_message(self, message):
        if self.network_encryption:
            message = self.network_encryption.decrypt(
                base64.urlsafe_b64decode(message)).decode('utf-8')
        else:
            message = message.decode('utf-8')
        key, data = message.split('§', maxsplit=1)
        tempfernet = Fernet(rsa.decrypt(
            base64.urlsafe_b64decode(key.encode('utf-8')), self.private))
        data = json.loads(base64.urlsafe_b64decode(tempfernet.decrypt(
            base64.urlsafe_b64decode(data.encode('utf-8')))).decode('utf-8'))
        data['args'] = [pickle.loads(base64.urlsafe_b64decode(
            arg.encode('utf-8'))) for arg in data['args']]
        data['kwargs'] = {k: pickle.loads(base64.urlsafe_b64decode(
            data['kwargs'][k].encode('utf-8'))) for k in data['kwargs'].keys()}
        
        if data['path'] in self.endpoints.keys():
            try:
                aspec = inspect.getfullargspec(self.endpoints[data['path']]) # I see you <3
                if 'node' in aspec.kwonlyargs or aspec.varkw:
                    data['kwargs']['node'] = self
                if 'originator' in aspec.kwonlyargs or aspec.varkw:
                    data['kwargs']['originator'] = [data['originator'], data['originator_name']]
                
                value = self.endpoints[data['path']](*data['args'], **data['kwargs'])
                if type(value) == SpearResponse:
                    status = value.status
                    value = value.data
                else:
                    status = 200

                return_data = {
                    'type': 'response',
                    'originator': self.id,
                    'originator_name': self.name,
                    'originator_key': base64.urlsafe_b64encode(self.public.save_pkcs1()).decode('utf-8'),
                    'target': data['originator'],
                    'result_status': status,
                    'result': base64.urlsafe_b64encode(pickle.dumps(value)).decode('utf-8')
                }
            except:
                return_data = {
                    'type': 'response',
                    'originator': self.id,
                    'originator_name': self.name,
                    'originator_key': base64.urlsafe_b64encode(self.public.save_pkcs1()).decode('utf-8'),
                    'target': data['originator'],
                    'result_status': 500,
                    'result': f'Remote function encountered an unexpected error: {traceback.format_exc()}'
                }
        else:
            return_data = {
                'type': 'response',
                'originator': self.id,
                'originator_name': self.name,
                'originator_key': base64.urlsafe_b64encode(self.public.save_pkcs1()).decode('utf-8'),
                'target': data['originator'],
                'result_status': 404,
                'result': f'Path "{data["path"]}" not found.'
            }
        encoded_response = base64.urlsafe_b64encode(json.dumps(return_data).encode('utf-8'))
        encrypted_response = tempfernet.encrypt(encoded_response)
        packed_response = base64.urlsafe_b64encode(encrypted_response)
        if self.network_encryption:
            packed_response = base64.urlsafe_b64encode(self.network_encryption.encrypt(packed_response))
        return packed_response
        

    def check_one_relay(self, relay):  # Function to check individual relays
        if not relay in self.relays.keys():
            return
        if self.relays[relay]['last_reply'] + 2 < time.time():
            self.relays[relay]['public_key'] = None
        if ':' in relay:
            host = relay.split(':')[0]
            port = int(relay.split(':')[1])
        else:
            host = relay
            port = 2201
        if self.relays[relay]['public_key'] == None:
            try:
                sock = create_connection((host, port), timeout=2)
            except TimeoutError:
                self.relays[relay]['public_key'] = None
                return
            sock.sendall(b'RSAREQUEST\n')
            while True:
                dat = sock.recv(1024)
                if not dat:
                    break
                dat = dat.strip()
                try:
                    self.relays[relay]['public_key'] = rsa.PublicKey.load_pkcs1(
                        base64.urlsafe_b64decode(dat))
                    break
                except:
                    pass
            sock.close()
        try:
            sock = create_connection((host, port), timeout=2)
        except TimeoutError:
            self.relays[relay]['public_key'] = None
            return
        packet = json.dumps({
            'peer_id': self.id,
            'peer_name': self.name,
            'network': self.network_name,
            'public_key': base64.urlsafe_b64encode(self.public.save_pkcs1()).decode('utf-8'),
            'relays': list(self.relays.keys()),
            'advertise': self.advertise
        })
        packet = 'PING:' + packet
        tfk = Fernet.generate_key()
        tempfernet = Fernet(tfk)
        enc = rsa.encrypt(tfk, self.relays[relay]['public_key'])
        to_send = base64.urlsafe_b64encode(
            enc)+'§'.encode('utf-8')+base64.urlsafe_b64encode(tempfernet.encrypt(packet.encode('utf-8')))+b'\n'
        sock.sendall(to_send)
        packet_response = ''
        while True:
            dat = sock.recv(1024)
            if not dat:
                break
            packet_response += dat.decode('utf-8').strip()
        if packet_response == 'error':
            self.relays[relay]['public_key'] = None
            return
        decrypted = tempfernet.decrypt(
            base64.urlsafe_b64decode(packet_response.encode('utf-8')))
        processed = json.loads(decrypted)

        for r in processed['relays']:
            if not r in self.relays.keys():
                if ':' in r:
                    r_ip = r
                else:
                    r_ip = r + ':2201'
                self.relays[r_ip] = {
                    'last_reply': time.time(),
                    'public_key': None
                }
        for p in processed['peers'].keys():
            if not p in self.peers['remote'] and p != self.id:
                self.peers['remote'][p] = {
                    'id': p,
                    'name': processed['peers'][p][0],
                    'network': self.network_name,
                    'public_key': rsa.PublicKey.load_pkcs1(base64.urlsafe_b64decode(processed['peers'][p][1])),
                    'relays': [relay],
                    'type': 'remote'
                }
            elif p in self.peers['remote'] and not relay in self.peers['remote'][p]['relays']:
                self.peers['remote'][p]['relays'].append(relay)
        
        to_process = []
        while len(processed['buffer']) > 0:
            item = processed['buffer'].pop()
            if item['type'] == 'resp':
                self.responses[item['id']] = item.copy()
            else:
                to_process.append(item.copy())
        
        with ThreadPoolExecutor() as executor:
            [executor.submit(self.process_single_remote_message, m, relay) for m in to_process]

        self.relays[relay]['last_reply'] = time.time()
        sock.close()
    
    def process_single_remote_message(self, message, relay):
        mid = message['id']
        origin = message['originator']
        data = message['data'].encode('utf-8')

        response_message = self.process_message(data)
        try:
            sock = create_connection([relay.split(':')[0], int(relay.split(':')[1])], timeout=2)
        except TimeoutError:
            self.relays[relay]['public_key'] = None
            return
        packet = json.dumps({
            'originator': self.id,
            'target': origin,
            'network': self.network_name,
            'id': mid,
            'data': response_message.decode('utf-8')
        })
        packet = 'RESP:' + packet
        tfk = Fernet.generate_key()
        tempfernet = Fernet(tfk)
        enc = rsa.encrypt(tfk, self.relays[relay]['public_key'])
        to_send = base64.urlsafe_b64encode(
            enc)+'§'.encode('utf-8')+base64.urlsafe_b64encode(tempfernet.encrypt(packet.encode('utf-8')))+b'\n'
        sock.sendall(to_send)
        sock.close()


    def check_relays(self):  # Relay checker thread
        while self.running:
            with ThreadPoolExecutor() as executor:
                [executor.submit(self.check_one_relay, r)
                 for r in list(self.relays.keys())]

    async def handle_local_connections(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        data = await reader.readline()
        message = data.strip()
        response = self.process_message(message) + b'\n'
        writer.write(response)
        await writer.drain()
        writer.close()

    async def run_local_server(self):
        self.server = await asyncio.start_server(self.handle_local_connections, ip(), self.service_port)
        async with self.server:
            await self.server.serve_forever()

    def peer(self, target='*'):
        return Peer(self, target=target)

    def serve_forever(self):  # Run SPEAR
        self.running = True
        if self.advertise and self.use_local:
            self.threads['advertiser'] = threading.Thread(
                target=self.run_advertiser, daemon=True
            )
        if self.use_local:
            self.threads['discoverer'] = threading.Thread(
                target=self.discover_local_loop, daemon=True
            )
        self.threads['peer_check'] = threading.Thread(
            target=self.check_peer_timeouts, daemon=True
        )
        if self.use_remote:
            self.threads['relay_check'] = threading.Thread(
                target=self.check_relays, daemon=True
            )
        if self.use_local:
            self.threads['local_server'] = threading.Thread(
                target=asyncio.run, args=[self.run_local_server()], daemon=True
            )
        [t.start() for t in self.threads.values()]
    
    def close(self):
        self.running = False
        
