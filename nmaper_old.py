import pyodbc
import logging
import time
import subprocess
import threading
import sys


def error_handler(function):
    def wrapper(*args, **kwargs):
        try:
            result = function(*args, **kwargs)
            return result
        except Exception as err:
            logging.error(time.ctime() + ' ' + str(err.args) + '\n')
            print(time.ctime() + ' An exception occurred. Check error.log')
            return -1
    return wrapper


def get_host_info(hostname: str, command='nmap -T4 -F') -> str:
    result = ''
    with subprocess.Popen(command + ' ' + hostname, stdout=subprocess.PIPE) as process:
        result = process.stdout.read().decode(CMD_ENCODING)
    return result


def add_host(ip: str, port: str, transport: str, status: str, service: str):
    print(ip, port, service, transport, status)
##    query_str = 'INSERT INTO dbo.{0} (ip, port, transport, status, service) VALUES ({1}, {2}, {3}, {4}, {5})'.format(TABLE,
##                                                                                                                "'" + ip + "'",
##                                                                                                                "'" + port + "'",
##                                                                                                                "'" + transport + "'",
##                                                                                                                "'" + status + "'",
##                                                                                                                "'" + service + "'",
##                                                                                                                )
##    cursor.execute(query_str)
##    cnxn.commit()


def get_octet_start_end(octet: str) -> tuple:
    if not ('-' in octet):
        min_int = int(octet)
        max_int = int(octet)
    else:
        octet_data = octet.split('-')
        min_int = int(octet_data[0])
        max_int = int(octet_data[1])
    if min_int < 0:
        raise RuntimeError('Octet can\'t be less than 0')
    if max_int > 255:
        raise RuntimeError('Octet can\'t be more than 255')
    return min_int, max_int


def inspect_diapason(diapason: str) -> int:
    addresses = 0
    octets = diapason.split('.')
    d1 = get_octet_start_end(octets[0])
    d2 = get_octet_start_end(octets[1])
    d3 = get_octet_start_end(octets[2])
    d4 = get_octet_start_end(octets[3])
    for octet1 in range(d1[0], d1[1] + 1):
        for octet2 in range(d2[0], d2[1] + 1):
            for octet3 in range(d3[0], d3[1] + 1):
                for octet4 in range(d4[0], d4[1] + 1):
                    ip = str(octet1)+'.'+str(octet2)+'.'+str(octet3)+'.'+str(octet4)
                    print('scanning ' + ip)
                    data = get_host_info(ip)
                    if not (('Host seems down' in data) or ('All 100 scanned ports' in data)):
                        str_list = data.split('\r\n')
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
                                    add_host(ip, port, transport, status, service)
                    addresses += 1
                print('done ' + str(octet1) + '.' + str(octet2) + '.' + str(octet3) + '.' + str(d4[0]) + '-' + str(d4[1]))
            print('done ' + str(octet1) + '.' + str(octet2) + '.' + str(d3[0]) + '-' + str(d3[1]) + '.' + str(d4[0]) + '-' + str(d4[1]))
        print('done ' + str(octet1) + '.' + str(d2[0]) + '-' + str(d2[1]) + '.' + str(d3[0]) + '-' + str(d3[1]) + '.' + str(d4[0]) + '-' + str(d4[1]))
    print('done ' + str(d1[0]) + '-' + str(d1[1]) + '.' + str(d2[0]) + '-' + str(d2[1]) + '.' + str(d3[0]) + '-' + str(d3[1]) + '.' + str(d4[0]) + '-' + str(d4[1]))
    return addresses


@error_handler
def main(argv) -> int:

    if len(argv) < 2:
        raise RuntimeError('ip addresses diapason expected')

    addresses = inspect_diapason(argv[1])
    print('Scanning done. Scanned {0} addresses'.format(addresses))
    return 0


CMD_ENCODING = '866'
SERVER = 'ROUTER\TESTSERVER'
DATABASE = 'SCAN'
TABLE = 'SERVICES'
USERNAME = 'sa'
PASSWORD = '1234'
CONN_STR = 'DRIVER={ODBC Driver 17 for SQL Server};SERVER=' + SERVER + ';DATABASE=' + DATABASE + ';UID=' + USERNAME+ ';PWD=' + PASSWORD
argv = __file__, '192.168.0.1-255'

# if __name__ == '__main__':
#     logging.basicConfig(filename='error.log', filemode='a')
#
#     try:
#         cnxn = pyodbc.connect(CONN_STR)
#         cursor = cnxn.cursor()
#     except Exception as err:
#         logging.error(time.ctime() + ' ' + str(err.args) + '\n')
#         print(time.ctime() + ' An exception occurred. Check error.log')

main(argv)
