import subprocess
import threading

import utils
import psycopg2
from time import time
import sys


def get_host_info(hostname: str, command=''):
    result = ''
    with subprocess.Popen(command + ' ' + hostname, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        print(process.returncode)
        result_stdout = process.stdout.read().decode(CMD_ENCODING)
        result_stderr = process.stderr.read().decode(CMD_ENCODING)
    return result_stdout, result_stderr


def add_host(ip: str, port: str, transport: str, status: str, service: str):
    print(ip, service, port, status, transport)
    #global connection, cursor
    #print(ip, port, service, transport, status)
    #sql = 'INSERT INTO {0} VALUES(default, \'{1}\', \'{2}\', {3}, \'{4}\', \'{5}\');'.format(TABLENAME, ip, service, port, status, transport)
    #execute_query(sql)


def execute_query(sql):
    global connection, cursor
    try:
        cursor.execute(sql)
        connection.commit()
    except psycopg2.InterfaceError:
        connection = psycopg2.connect(dbname=DBNAME, user=USER, password=PASSWORD, port=PORT, host=HOST)
        cursor = connection.cursor()
        execute_query(sql)


def inspect_diapason(start, amount):
    global scans_per_thread, errors
    curr_ip10 = start
    scans = 0
    for i in range(amount):
        curr_ip_hex = bytes.fromhex(hex(curr_ip10)[2:].zfill(8))
        curr_ip = utils.hexToIp(curr_ip_hex)
        #print('scanning', curr_ip)
        stdout, stderr = get_host_info(curr_ip, command=' '.join(nmap_args))
        if stderr:
            if not errors:
                print('STDERR', stderr)
                errors = True
            return
        if not (('Host seems down' in stdout) or ('All 100 scanned ports' in stdout)):
            str_list = stdout.split('\r\n')
            for str_i in range(len(str_list)):
                if 'PORT' in str_list[str_i] and 'STATE' in str_list[str_i] and 'SERVICE' in str_list[str_i]:
                    for str_i in range(str_i + 1, len(str_list)):
                        if 'MAC Address' in str_list[str_i] or not str_list[str_i]:
                            break
                        service_data = str_list[str_i].split()
                        port = service_data[0].split('/')[0]
                        transport = service_data[0].split('/')[1]
                        status = service_data[1]
                        service = service_data[2]
                        add_host(curr_ip, port, transport, status, service)
                    #print('host {0} scanned'.format(curr_ip))
            scans += 1
        curr_ip10 += 1
    scans_per_thread.append(scans)


CMD_ENCODING = '866'
start_ip = '192.168.0.1'
end_ip = '192.168.0.255'
nmap_args = ['nmap', '-T4', '-wefwef']
# 10.0.0.1 - 10.0.255.255
# 10.0.0.1 - 10.1.255.255
# 10.0.0.1 - 10.2.255.255

threads = 32
start_ip10 = int.from_bytes(utils.ipToHex(start_ip), 'big')
end_ip10 = int.from_bytes(utils.ipToHex(end_ip), 'big')
ips_amount = end_ip10 - start_ip10
ips_per_thread = [ips_amount//threads] * threads
ips_per_thread[-1] += ips_amount % threads + 1
ts = []
scans_per_thread = []
DBNAME = 'nmapscans'
TABLENAME = 'scans10_8'
HOST = 'localhost'
USER = 'postgres'
PASSWORD = '123q'
PORT = 5432
errors = False

start_time = time()

connection = psycopg2.connect(dbname=DBNAME, user=USER, password=PASSWORD, port=PORT, host=HOST)
cursor = connection.cursor()

for thread in range(threads):
    start = start_ip10 + ips_amount//threads * thread
    t = threading.Thread(target=inspect_diapason, args=(start, ips_per_thread[thread]))
    ts.append(t)

for t in ts:
    t.start()
for t in ts:
    t.join()
print(f'{sum(scans_per_thread)} addresses added in {time()-start_time} seconds')
connection.close()
# <start> <end> [threads] [per threaad calls]  nmap params