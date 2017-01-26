# smith
A client/server style agent meant for testing connectivity to and from a machine on a network.

## Installation
```python setup.py install``` or ```pip install .``` should install smith.
Note: If you want to use the tcp/udp protocol options, you'll need to install scapy and it's dependencies.
Ubuntu has 'apt-get install python-scapy'.  You can also pip install scapy, but I don't know if that
installs all dependencies on all OS's.  I didn't include scapy in the requires because the 'rest' option
doesn't utilize it, and is sufficient for a lot of usecases on its own.

--

## Functions: ping and listen

## ping
```bash
$: smith ping -h

usage: 
  Initiate a port-specific ping against a listening agent

positional arguments:
  port                  The port the remote agent is listening on
  destination           IPv4 address of the server the remote agent is
                        listening on
  {TCP,UDP,REST}        Protocol to use to contact the remote agent. TCP and
                        UDP use raw sockets which will bypass IPTABLES rules.

optional arguments:
  -h, --help            show this help message and exit
  -t TIMEOUT, --timeout TIMEOUT
                        Seconds to wait for response from server before giving
                        up. Zero means 'wait forever'
```
### Example
```bash
$: smith ping 12345 127.0.0.1 REST --timeout 10
```
---

## listen
```bash
$: smith listen -h
usage: 
 Server-side: listen for incoming ping requests from remote client.

positional arguments:
  port            The port the remote client is pinging
  {TCP,UDP,REST}  Protocol to use to contact the remote agent.TCP and UDP use
                  raw sockets which will bypass IPTABLES rules.

optional arguments:
  -h, --help      show this help message and exit
```

### Example
```bash
$: smith ping 12345 127.0.0.1 REST --timeout 10
```
