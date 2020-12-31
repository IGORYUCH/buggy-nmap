from subprocess import Popen, PIPE
from threading import Thread, Lock
from time import time
from sys import argv
from re import match
import utils


def get_host_info(hostname: str, command: str):
    with Popen(command + ' ' + hostname, stdout=PIPE, stderr=PIPE) as process:
        result_stdout = process.stdout.read().decode(CMD_ENCODING)
        result_stderr = process.stderr.read().decode(CMD_ENCODING)
    return result_stdout, result_stderr


def inspect_diapason(start_adress, amount):
    scanning_adress_int10 = start_adress
    for i in range(amount):
        scanning_adress_hex = bytes.fromhex(hex(scanning_adress_int10)[2:].zfill(8))
        scanning_adress = utils.hex_to_ip(scanning_adress_hex)
        stdout, stderr = get_host_info(scanning_adress, ' '.join(nmap_args))

        if stderr:
            if lock.acquire():
                print('stderr:', stderr)
            return

        strings_list = stdout.split('\r\n')
        for string in strings_list:
            if match(r'\d+/\w{3}\s+\w+\s+\w+', string):

                service_data = string.split()
                port = service_data[0].split('/')[0]
                transport = service_data[0].split('/')[1]
                status = service_data[1]
                service_name = service_data[2]

                scanned_services.append((scanning_adress, port, transport, status, service_name))

        print('scanned', scanning_adress)
        scanning_adress_int10 += 1


def main():
    offset = 0
    for thread_adresses in utils.distribute_evenly(threads, adresses_amount):
        start_adress = diapason_start_int10 + offset
        thread = Thread(target=inspect_diapason, args=(start_adress, thread_adresses))
        threads_list.append(thread)
        offset += thread_adresses

    for thread in threads_list:
        thread.start()

    for thread in threads_list:
        thread.join()

    for service in scanned_services:
        print(service)

    print(f'Scanned in {round(time() - start_time, 2)} seconds')


threads = int(argv[1])
diapason = argv[2]
diapason_start, diapason_end = utils.get_start_end(diapason)
nmap_args = ['nmap'] + argv[3:]
scanned_services = []

diapason_start_int10 = int.from_bytes(utils.ip_to_hex(diapason_start), 'big')
diapason_end_int10 = int.from_bytes(utils.ip_to_hex(diapason_end), 'big')

adresses_amount = diapason_end_int10 - diapason_start_int10 + 1
threads_list = []
lock = Lock()

start_time = time()
CMD_ENCODING = '866'

if __name__ == '__main__':
    main()
