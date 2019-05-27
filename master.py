from flask import Flask, request
from flask_restful import Resource, Api
from sqlalchemy import create_engine, select, insert, MetaData, Table, Column, TEXT
import requests
import random
import string
import os
import json
import time
from multiprocessing import Process
import socket
from contextlib import closing
from minion import run_minion

db_name = 'master.db'
master_db = 'sqlite:///' + db_name
db_connect = create_engine(master_db)
app = Flask(__name__)
api = Api(app)


##################  API classes #####################


class NewSession(Resource):
    def get(self):
        """"
        Creates new session.
        :return: json file with session_id
        """
        check_if_db_exists()
        conn = db_connect.connect()  # connect to database
        new_session_id = self.__get_new_session(conn)
        try:
            self.__create_new_session(new_session_id, conn)
        except():
            return {'status': 'Error: failed to create new session!'}
        return {
            'status': 'Session successfully created!',
            'session_id': new_session_id
        }

    def __create_new_session(self, new_session_id, conn):
        """
        Initializes status, and creates session directory
        :param new_session_id: new session id
        :param conn: db connection
        """
        initial_status = 'ready'
        ins = sessions.insert().values(session_id=new_session_id)
        conn.execute(ins)
        if not os.path.exists('sessions'):
            os.mkdir('sessions')
        session_dir = 'sessions/' + new_session_id
        if not os.path.exists(session_dir):
            os.mkdir(session_dir)
        json_status = {'status': initial_status}
        json_output = json.dumps(json_status)
        with open(session_dir + '/session.json', 'w') as f:
            f.write(json_output)

    def __get_new_session(self, conn):
        """
        Chooses random new session id.
        :param conn: db connection
        :return: new session id
        """
        while True:
            new_session_id = self.__random_string()
            try:
                sel = select([sessions.c.session_id]).where(sessions.c.session_id == new_session_id)
                query = conn.execute(sel)
            except():
                return {'status': 'Error: failed to create new session!'}
            if len(query.cursor.fetchall()) == 0:
                break
        return new_session_id

    def __random_string(self, string_length=10):
        """
        Generate a random string of fixed length.
        :param string_length: string length
        :return: random string
        """
        letters = string.hexdigits
        return ''.join(random.sample(letters, string_length))


class Status(Resource):
    def get(self, session_id):
        """
        Gets status of input session.
        :param session_id: session id
        :return: status is either:
                 'busy' - if still calculating
                 'ready' - if ready for calculation
                 'finished' - returned with list of passwords
                 'error' - if error handled
        """
        check_if_db_exists()
        conn = db_connect.connect()
        try:
            sel = select([sessions.c.session_id]).where(sessions.c.session_id == session_id)
            query = conn.execute(sel)
            if len(query.cursor.fetchall()) == 0:
                return {'status': 'error', 'message': 'Error: session not found!'}
        except():
            return {'status': 'error', 'message': 'Error: failed to create new session!'}
        with open('sessions/' + session_id + '/session.json', 'r') as f:
            output = json.load(f)
        return output


class UploadFile(Resource):
    def post(self, session_id):
        """
        Uploads hashes file. Then, calculates all possible hashes, and stops when
        calculating relevant hashes.
        :param session_id: session id
        :return: status is either:
                 'busy' - if started calculating
                 'occupied' - if session already in use
                 'error' - if error handled
        """
        if len(request.files) == 0:
            return {'status': 'error', 'message': 'Error: no input file!'}
        elif len(request.files) > 1:
            return {'status': 'error', 'message': 'Error: only one file can be uploaded in each request!'}
        with open('sessions/' + session_id + '/' + session_filename, 'r') as f:
            session_json = json.load(f)
        if session_json['status'] == 'busy':
            return {'status': 'occupied', 'message': 'Session is occupied!'}

        check_if_db_exists()
        update_status(session_id, 'busy')
        file = list(request.files.to_dict().values())[0]  # gets input file

        # get dict of hashes
        try:
            hashes = self.__get_hash_dict(file)
        except:
            return {'status': 'error', 'message': 'Error: one of the hashes is illegal!'}

        minions = self.__create_minions(session_id)  # generate minions
        self.__start_minions(minions)  # start minions
        self.__start_calculating(minions)  # split range to minions
        self.__get_hashes(minions, hashes, session_id)  # check hashes
        self.__check_connectivity(minions, session_id)  # check connectivity to minions
        with open('sessions/' + session_id + '/' + session_filename, 'r') as f:
            session_json = json.load(f)
        return session_json

    def __start_minions(self, minions):
        """
        Starts minions processes.
        :param minions: a list of minion objects
        """
        for minion in minions:
            m = Process(target=run_minion, args=(minion['port'], minion['minion_id'], minion['session_id']))
            m.start()
            processes.append(m)

    def __get_hashes(self, minions, hashes, session_id):
        """
        Calls deciphering process.
        :param minions: a list of minion objects
        :param hashes: a list of hashes
        :param session_id: session id
        """
        p = Process(target=decipher_hashes, args=(minions, hashes, session_id), )
        p.start()
        processes.append(p)

    def __start_calculating(self, minions):
        """
        Calls calculation for all valid passwords.
        :param minions: a list of minion objects
        """
        min_value = 0
        max_value = 99999999
        start_calculating(minions, min_value, max_value, first=True)

    def __check_connectivity(self, minions, session_id):
        """
        Calls checking connectivity process.
        :param minions: a list of minion objects
        :param session_id: session id
        """
        p = Process(target=check_connectivity, args=(minions, session_id))
        p.start()
        processes.append(p)

    def __get_hash_dict(self, file):
        """
        Gets dictionary of valid hashes.
        :param file: input file
        :return: list of valid hashes
        """
        lines = file.stream.readlines()
        hashes = {}
        for i, line in enumerate(lines):
            hash = line.decode("utf-8").replace('\n', '').replace('\r', '').replace(' ', '')
            hashes[i] = hash
            if len(hash) != 32:
                raise ValueError
        return hashes

    def __create_minions(self, session_id):
        """
        Creates a list of minion objects
        :param session_id: session id
        :return: a list of minion objects
        """
        minions, minion_ports = [], []
        num_of_minions = get_num_of_minions()
        for i in range(num_of_minions):
            free_port = find_free_port(minion_ports)
            minion = {
                'minion_id': i,
                'session_id': session_id,
                'url': 'http://localhost',
                'port': free_port,
                'timeouts': 0
            }
            minions.append(minion)
            minion_ports.append(free_port)
        return minions


##################  general purpose functions #####################


def get_num_of_minions():
    """
    Gets number of used minions from json file.
    :return: number of used minions
    """
    with open(json_filename, 'r') as f:
        json_file = json.load(f)
    return json_file['minions']


def find_free_port(used_ports):
    """
    Gets a free port.
    :param used_ports: list of already selected ports
    :return: a free port
    """
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        while True:
            s.bind(('localhost', 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if s.getsockname()[1] not in used_ports:
                break
        return s.getsockname()[1]


def decipher_hashes(minions, hashes, session_id):
    """
    Checks for each hash in the minions until they all found.
    :param minions: a list of minion objects
    :param hashes: a dictionary of valid hashes
    :param session_id: session id
    """
    passwords = []
    for hash in hashes.values():
        found = False
        while not found:
            found = check_for_hash_in_minions(minions, hash, passwords)
            if not minions:
                update_status(session_id, 'failed')
                stop_master(minions)
                return
    update_status(session_id, 'finished', passwords)
    print("Hash file cracking was successfully finished!")
    stop_master(minions)


def stop_master(minions):
    """
    Stops minions and other background processes.
    :param minions: a list of minion objects
    """
    stop_calculation_in_minions(minions)
    for process in processes:
        process.terminate()
    processes.clear()


def check_for_hash_in_minions(minions, hash, passwords):
    """
    Every 3 seconds look for a hash in the minions.
    :param minions: a list of minion objects
    :param hash: a valid hash
    :param passwords: a list of found passwords
    :return: True if hash found. otherwise, False.
    """
    found = False
    for i, minion in enumerate(minions):
        endpoint = minion['url'] + ':' + str(minion['port']) + \
                   '/check_status'
        minion_json = {'status': None}
        try:
            r = requests.get(url=endpoint)
            minion_json = r.json()
        except:
            pass
        endpoint = minion['url'] + ':' + str(minion['port']) + \
                   '/get_hash/' + str(hash)
        try:
            r = requests.get(url=endpoint)
            content = r.json()
            if content['status'] == 'found':
                passwords.append(content['password'])
                found = True
                return found
            if minion_json['status'] == 'finished' and content['status'] == 'not found':
                minions.pop(i)
                break
        except:
            if minion['timeouts'] == 3:
                minions.pop(i)
                break
            minion['timeouts'] += 1
    time.sleep(3)
    return found


def stop_calculation_in_minions(minions):
    """
    Sends stop requests to minions.
    :param minions: a list of minion objects
    """
    for i, minion in enumerate(minions):
        endpoint = minion['url'] + ':' + str(minion['port']) + \
                   '/stop'
        try:
            requests.post(url=endpoint)
            print('Calculation in minion ' + str(minion['minion_id']) + ' has been stopped.')
        except:
            print('Error: failed to stop calculation in minion ' + str(i) + '.')


def update_status(session_id, new_status, passwords=None):
    """
    Updates session json status.
    :param session_id: session id
    :param new_status: a status string
    :param passwords: a list of found passwords (if status is 'finished')
    """
    with open('sessions/' + session_id + '/' + session_filename, 'r') as f:
        session_json = json.load(f)
    session_json['status'] = new_status
    if passwords:
        session_json['passwords'] = passwords
    with open('sessions/' + session_id + '/' + session_filename, 'w') as f:
        new_session_json = json.dumps(session_json)
        f.write(new_session_json)


def start_calculating(minions, min_value, max_value, first=False):
    """
    Splits the input range to the input minions and send requests to minions
    to calculate them.
    :param minions: a list of minion objects
    :param min_value: minimal value
    :param max_value: maximal value
    :param first: determines if this is the first call of this fuction
    """
    minions_len = len(minions)
    if minions_len == 0:
        print('Error: no available minions found.')
        return
    num_of_values = max_value - min_value + 1
    num_of_minion_values = int(num_of_values / minions_len)
    carry = 1 if num_of_values % minions_len != 0 else 0
    for i, minion in enumerate(minions):
        start = min_value + i*num_of_minion_values
        end = min_value + (i+1)*num_of_minion_values - 1
        if first:
            minion['start'] = [start]
            minion['end'] = [end]
        else:
            minion['start'] += [start]
            minion['end'] += [end]
        if i == minions_len - 1:
            end += carry
        endpoint = minion['url']+':'+str(minion['port'])+'/start_calculation/'+str(start)+'_'+str(end)
        try:
            requests.post(url=endpoint)
        except:
            print('Error: minion ' + str(minion['minion_id']) + ' did\'nt receive start command.')


def check_connectivity(minions, session_id):
    """
    Checks connectivity to minions each 2 seconds. If a minion reached timeout,
    it's calculation range will be split to other minions
    :param minions: a list of minion objects
    :param session_id: session id
    """
    while len(minions) and get_session_status(session_id) != 'finished':
        for i, minion in enumerate(minions):
            endpoint = minion['url'] + ':' + str(minion['port']) + '/check_status'
            try:
                r = requests.get(url=endpoint)
                minion_json = r.json()
                if minion_json['status'] == 'finished':
                    minions.pop(i)
                    break
                minion['timeouts'] = 0
            except:
                minion['timeouts'] += 1
                if minion['timeouts'] == 3:
                    print('Minion ' + str(minion['minion_id']) + ' reached timeout!')
                    print('Splitting minion\'s ' + str(minion['minion_id']) + ' job to other minions...')
                    starts = minion['start']
                    ends = minion['end']
                    minions.pop(i)
                    for j, start in enumerate(starts):
                        end = ends[j]
                        start_calculating(minions, start, end)
                    break
        time.sleep(2)


def get_session_status(session_id):
    """
    Checks status of session json file.
    :param session_id: session id
    :return: session json file status
    """
    with open('sessions/' + session_id + '/' + session_filename, 'r') as f:
        session_json = json.load(f)
    return session_json['status']


def check_if_db_exists():
    """
    Create new session db if not exists.
    """
    if not os.path.exists(db_name):
        metadata.create_all(db_connect)


json_filename = 'master.json'
session_filename = 'session.json'
processes = []
metadata = MetaData()
sessions = Table('sessions', metadata,
                 Column('session_id', TEXT, primary_key=True))

# API urls
api.add_resource(NewSession, '/new_session')  # starts a new session
api.add_resource(Status, '/sessions/<session_id>/status')  # get session status
api.add_resource(UploadFile, '/sessions/<session_id>/upload')  # upload hash file

if __name__ == '__main__':
    with open(json_filename, 'r') as f:
        master_json = json.load(f)
    app.run(port=str(master_json['port']))
