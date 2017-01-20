from common import *

resp = send_and_listen(
    destination_ip='23.253.95.196',
    destination_port=12345,
    protocol=CONST.TCP)
print resp


#FOR THE CLIENT:
#http://www.secdev.org/projects/scapy/doc/usage.html#send-and-receive-packets-sr
