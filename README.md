# buggy-nmap

This script is indended to get around [#1385](https://github.com/nmap/nmap/issues/1385) issue of nmap and provides reusable output to other applications. It calls nmap 
instance for each ip-address (instead of diapason of addresses) in addresses diapason you specified that's how bug can be get arounded.
That is slower than clear nmap usage but you can pass on threads/tasks amount to speed it up.

There are asynchronous and threaded versions of script. Asynchronous is slighty faster than threaded version (maybe)

# Usage

The common usage looks as follows:
```
nmaper.py 12 192.168.0.1-255 -T4 -F
```
Where:

`12` - number of threads/tasks you'd like your program will be "parallelized"

`192.168.0.1-255` - ip-diapason to scan

`-T4 -F` - some args nmap will receive


# Output

The common output looks as follows:
```
('192.168.0.110', '554', 'tcp', 'open', 'rtsp')
...
Scanned in 55.69 seconds
```
These are represents data about services parsed from nmap output:

Where:

`192.168.0.110` - ip-address on which service runs

`554` - port on host

`tcp` - Transport layer protocol

`open` - current status of service

`rtsp` - name of service





