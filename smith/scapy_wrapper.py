from scapy.all import *

class CONST(object):
    """
    These strings serve as the known payloads for the packets the client and server will send
    eachother.
    """
    initiator_string = "INIT PACKET"
    responder_string = "RESP PACKET"

class Reactions(object):

    @staticmethod
    def respond_tcp(packet):
        """
        If a TCP initiator packet is detected, create and send a TCP response packet to the
        originator of the initiator packet at the originating port.

        A TCP initiator packet is denoted by the initiator_string being it's only payload
        """

        if not packet.payload.load == CONST.initiator_string:
            return

        src=None
        dst=None
        sport=None
        dport=None
        if 'IP' in packet:
            src=packet['IP'].src
            dst=packet['IP'].dst
        if 'TCP' in packet:
            sport=packet['TCP'].sport
            dport=packet['TCP'].dport
        elif 'UDP' in packet:
            sport=packet['UDP'].sport
            dport=packet['UDP'].dport

        send(
            IP(dst=src, src=dst)
            /TCP(dport=sport, sport=dport)
            /Raw(load=CONST.responder_string) )

    @staticmethod
    def respond_udp(packet):
        """
        If a UDP initiator packet is detected, create and send a UDP response packet to the
        originator of the initiator packet at the originating port.

        A UDP initiator packet is denoted by the initiator_string being it's only payload
        """
        # create a packet
        # send it back to the originator of this packet

        if not packet.payload.load == CONST.initiator_string:
            return

        src=None
        dst=None
        sport=None
        dport=None
        if 'IP' in packet:
            src=packet['IP'].src
            dst=packet['IP'].dst
        if 'UDP' in packet:
            sport=packet['UDP'].sport
            dport=packet['UDP'].dport

        send(
            IP(dst=src, src=dst)
            /UDP(dport=sport, sport=dport)
            /Raw(load=CONST.responder_string) )

    @staticmethod
    def return_printable(packet):
        # For testing and debug purposes.  Eventually, I plan to add more
        # methods for doing stuff other than just returning the packet,
        # including possibly chaining reaction methods.
        return "Packet {0} ==> {1}: {2}".format(
            packet[0][1].src, packet[0][1].dst, packet.payload.load)


def send_and_listen(
        destination_ip=None,
        destination_port=None,
        protocol=None,
        timeout=0):

    """
    Craft and send an initiator packet of type 'protocol' to the given 'destination_ip' at
    'destination_port'.
    Once sent, method will listen for a response for 'timeout' seconds (0 == Indefinitely).
    If a response packet is detected, response packet is returned.
    """

    resp = None
    if protocol == 'tcp':
        resp = sr(
            IP(dst=destination_ip)
            /TCP(dport=destination_port)
            /Raw(load=CONST.initiator_string),
            timeout=timeout
        )
    elif protocol == 'udp':
        resp = sr(
            IP(dst=destination_ip)
            /UDP(dport=destination_port)
            /Raw(load=CONST.initiator_string),
            timeout=timeout
        )
    else:
        print(
            "Request to send/listen for unsupported "
            "protocol: {0}".format(protocol))
        exit()

    return resp

def listen(
        port=None,
        protocol=None,
        interface=None,
        reaction=None,
        timeout=None,
        bpf_override=None):
    """
    Uses scapy lib's sniff() method to filter packets across all interfaces.  Sniff() will run the
    'reaction' method when a sniffed packet matches the given parameters:
    destination port, interface, or protocol.

    bpf_override is a string that adheres to the Berkeley Packet Filter syntax
    (http://biot.com/capstats/bpf.html)
    default bpf is 'ip dst port {port}'
    """

    timeout = None if timeout == 0 else timeout
    interface_str = "on {0}".format(interface) if interface else ""
    proto_str = "{0}".format(protocol) if protocol else ""
    port_str = "dst port {0}".format(port) if port else ""
    bpf = "{interface} {protocol} {port}".format(
            interface = interface_str, protocol=proto_str, port=port_str)
    bpf = bpf_override if bpf_override else bpf
    bpf = bpf.strip()

    # Setup sniff, filtering for IP traffic
    # example: scapy_all.sniff(filter="ip",prn=customAction)
    sniff(filter=bpf, prn=reaction, timeout=timeout)
