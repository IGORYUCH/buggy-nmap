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


async def inspect_diapason(start_adress, amount):
    scanning_adress_int10 = start_adress
    for i in range(amount):
        scanning_adress_hex = bytes.fromhex(hex(scanning_adress_int10)[2:].zfill(8))
        scanning_adress = utils.hex_to_ip(scanning_adress_hex)
        stdout, stderr = await get_host_info(scanning_adress, ' '.join(nmap_args))

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

                scanned_services.append((scanning_adress, port, transport, status, service_name))

        print('scanned', scanning_adress)
        scanning_adress_int10 += 1


async def main():
    offset = 0
    for task_adresses in utils.distribute_evenly(tasks, adresses_amount):
        start_adress = diapason_start_int10 + offset
        task = asyncio.create_task(inspect_diapason(start_adress, task_adresses))
        offset += task_adresses
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
adresses_amount = diapason_end_int10 - diapason_start_int10 + 1

start_time = time()

if __name__ == '__main__':
    asyncio.run(main())
