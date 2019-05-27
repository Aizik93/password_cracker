from flask import Flask
from flask_restful import Resource, Api
from sqlalchemy import create_engine, select, insert, MetaData, Table, Column, TEXT
import json
from multiprocessing import Process
from hashlib import md5
import sys
import os


app = Flask(__name__)
api = Api(app)


##################  API classes #####################


class Calculate(Resource):
    def post(self, start_value, end_value):
        """
        Runs calculation service for a specific range.
        :param start_value: first value to calculate
        :param end_value: last value to calculate
        :return: status is either:
                 'busy' - if starts calculating
                 'error' - if error handled
        """
        start_value, end_value = int(start_value), int(end_value)
        engine_name = get_engine_name()
        if os.path.exists(engine_name):
            self.__clean_hashes()

        if not os.path.exists(json_filename):
            create_minion_json()
        engine_db_name = 'sqlite:///' + engine_name
        try:
            p = Process(target=calculate_range, args=(start_value, end_value, engine_db_name, m_id))
            p.start()
            processes.append(p)
        except:
            print('Error: failed to run calculation on minion ' + str(m_id) + '.')
            return {'status': 'error', 'message': 'calculation failed'}
        update_status('busy')
        return {'status': 'busy', 'message': 'calculation started'}

    def __clean_hashes(self):
        """
        Clears hashes table in minion's db.
        :throw: ValueError in case of failure
        """
        try:
            engine_db_name = 'sqlite:///' + get_engine_name()
            db_connect = create_engine(engine_db_name)
            conn = db_connect.connect()
            conn.execute(hashes.delete())
        except:
            print('Error: failed to clear sql table!')
            raise ValueError


class Hash(Resource):
    def get(self, hash):
        """
        Checks an input hash in the hashes table in db.
        :param hash: input hash
        :return: status is either:
                 'found' - if hash was found
                 'not found' - if hash was not found
                 'failed' - if an sql error handled
        """
        engine_db_name = 'sqlite:///' + get_engine_name()
        db_connect = create_engine(engine_db_name)
        conn = db_connect.connect()
        sel = select([hashes.c.password]).where(hashes.c.hash == hash)
        try:
            query = conn.execute(sel)
            entries = query.cursor.fetchall()
        except:
            return {'status': 'failed', 'message': 'sql error!'}
        if len(entries) == 0:
            return {'status': 'not found', 'message': 'password for ' + hash + ' not found!'}
        print('Valid password for ' + hash + ' is ' + entries[0][0])
        return {'status': 'found', 'password': entries[0][0]}


class Stop(Resource):
    def post(self):
        """
        Terminates running processes, and switch status back to ready.
        :return: status is either:
                 'ready' - if the session is ready for new hash file
                 'error' - if an error handled
        """
        for p in processes:
            try:
                p.terminate()
            except:
                return {'status': 'error',
                        'message': 'Error: failed to stop process ' + str(p.pid) + '!'}
        processes.clear()
        update_status('ready')
        return {'status': 'ready',
                'message': 'calculation has been successfully stopped!'}


class Status(Resource):
    def get(self):
        """
        Gets minion's status.
        :return: status json
        """
        minion_json = session_dir + str(m_id) + '.json'
        with open(minion_json) as f:
            output = json.load(f)
        return output


##################  general purpose functions #####################

def calculate_range(start, end, engine_name, minion_id):
    """
    Calculates hashes for passwords in the following format: 05XXXXXXXX of an input range,
    and save the results in the db.
    :param start: first value
    :param end: last value
    :param engine_name: db name
    """
    max_counter = 100
    rows = []
    db_connect = create_engine(engine_name)
    conn = db_connect.connect()
    metadata.create_all(db_connect)
    print('Calculating passwords for minion ' + str(minion_id) + '...')
    for num in range(start, end + 1):
        password = '05{0:08d}'.format(num)
        hash = md5(str.encode(password)).hexdigest()
        rows.append((hash, password))
        if len(rows) >= max_counter or num == end:
            ins = hashes.insert().values(rows)
            conn.execute(ins)
            rows = []

    update_status('finished')


def get_engine_name():
    """
    Gets db path.
    :return: db path
    """
    return session_dir + str(m_id) + '.db'


def update_status(new_status):
    """
    Updates status in minion's json.
    :param new_status: new minion status
    """
    with open(json_filename, 'r') as f:
        session_json = json.load(f)
    session_json['status'] = new_status
    with open(json_filename, 'w') as f:
        new_session_json = json.dumps(session_json)
        f.write(new_session_json)


def create_minion_json():
    """
    Creates new minion's json.
    """
    json_content = {'status': 'ready'}
    with open(json_filename, 'w') as f:
        output = json.dumps(json_content)
        f.write(output)


def run_minion(port_num, minion_id, session_id):
    """
    Runs new minion.
    :param port_num: Minion's port number
    :param minion_id: Minion's id
    :param session_id: session id
    """
    global port, m_id, session, session_dir, json_filename
    port = port_num
    m_id = minion_id
    session = session_id
    session_dir = 'sessions/' + session + '/'
    json_filename = session_dir + str(m_id) + '.json'
    app.run(port=str(port))


processes = []
metadata = MetaData()
hashes = Table('hashes', metadata, Column('hash', TEXT),
               Column('password', TEXT, primary_key=True))

# API urls
api.add_resource(Calculate, '/start_calculation/<start_value>_<end_value>')  # start minion calculation
api.add_resource(Hash, '/get_hash/<hash>')  # get password for hash
api.add_resource(Status, '/check_status')  # check minion status
api.add_resource(Stop, '/stop')  # stop minion calculation

