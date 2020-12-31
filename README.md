# buggy-nmap
This script is indended to get around #1385 issue of nmap and provides reusable output to other applications. It calls nmap 
instance for each ip-address (instead of diapason of addresses) in addresses diapason you specified that's how bug can be get arounded.
That is slower than clear nmap usage but you can pass on threads/tasks amount to speed it up.
