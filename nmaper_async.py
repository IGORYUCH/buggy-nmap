from time import time
from re import match
from sys import argv
import asyncio
import utils


async def get_host_info(hostname: str, command: str):
    process = await asyncio.create_subprocess_shell(
        command + ' ' + hostname,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
        )
    result_stdout, result_stderr = await process.communicate()
    return result_stdout.decode('utf-8'), result_stderr.decode('utf-8')


async def inspect_diapason(start_address, amount):
    scanning_address_int10 = start_address
    for i in range(amount):
        scanning_address_hex = bytes.fromhex(hex(scanning_address_int10)[2:].zfill(8))
        scanning_address = utils.hex_to_ip(scanning_address_hex)
        stdout, stderr = await get_host_info(scanning_address, ' '.join(nmap_args))

        if stderr:
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

                scanned_services.append((scanning_address, port, transport, status, service_name))

        print('scanned', scanning_address)
        scanning_address_int10 += 1


async def main():
    offset = 0
    for task_addresses in utils.distribute_evenly(tasks, addresses_amount):
        start_address = diapason_start_int10 + offset
        task = asyncio.create_task(inspect_diapason(start_address, task_addresses))
        offset += task_addresses
        tasks_list.append(task)
    await asyncio.gather(*tasks_list)

    for service in scanned_services:
        print(service)

    print(f'Scanned in {round(time() - start_time, 2)} seconds')


tasks = int(argv[1])
diapason = argv[2]
diapason_start, diapason_end = utils.get_start_end(diapason)
nmap_args = ['nmap'] + argv[3:]
scanned_services = []
tasks_list = []

diapason_start_int10 = int.from_bytes(utils.ip_to_hex(diapason_start), 'big')
diapason_end_int10 = int.from_bytes(utils.ip_to_hex(diapason_end), 'big')
addresses_amount = diapason_end_int10 - diapason_start_int10 + 1

start_time = time()

if __name__ == '__main__':
    asyncio.run(main())
