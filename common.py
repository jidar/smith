import multiprocessing
from scapy.all import *

class CONST(object):
    initiator_string = "<<INIT PACKET>>"
    responder_string = "<<RESP PACKET>>"
    TCP = "TCP"

class Reactions(object):

    """
    packet dir()
    ['__all_slots__', '__class__', '__contains__', '__delattr__', '__delitem__',
     '__div__', '__doc__', '__eq__', '__format__', '__getattr__', '__getattribute__',
      '__getitem__', '__gt__', '__hash__', '__init__', '__iter__', '__len__',
      '__lt__', '__metaclass__', '__module__', '__mul__', '__ne__', '__new__',
      '__nonzero__', '__rdiv__', '__reduce__', '__reduce_ex__', '__repr__',
      '__rmul__', '__rtruediv__', '__setattr__', '__setitem__', '__sizeof__',
      '__slots__', '__str__', '__subclasshook__', '__truediv__', '_answered',
      '_do_summary', '_name', '_overload_fields', '_pkt', '_show_or_dump',
      'add_payload', 'add_underlayer', 'aliastypes', 'answers', 'build',
      'build_done', 'build_padding', 'build_ps', 'canvas_dump', 'clone_with',
       'command', 'copy', 'copy_field_value', 'copy_fields_dict',
       'decode_payload_as', 'default_fields', 'default_payload_class',
       'delfieldval', 'direction', 'dispatch_hook', 'display', 'dissect',
       'dissection_done', 'do_build', 'do_build_payload', 'do_build_ps',
       'do_dissect', 'do_dissect_payload', 'do_init_fields', 'explicit',
       'extract_padding', 'fields', 'fields_desc', 'fieldtype', 'firstlayer',
       'fragment', 'from_hexcap', 'get_field', 'getfield_and_val',
       'getfieldval', 'getlayer', 'guess_payload_class', 'hashret', 'haslayer',
       'hide_defaults', 'init_fields', 'lastlayer', 'libnet', 'lower_bonds',
       'mysummary', 'name', 'original', 'overload_fields', 'overloaded_fields',
       'packetfields', 'payload', 'payload_guess', 'pdfdump', 'post_build',
       'post_dissect', 'post_dissection', 'post_transforms', 'pre_dissect',
       'psdump', 'raw_packet_cache', 'raw_packet_cache_fields',
       'remove_payload', 'remove_underlayer', 'route', 'self_build',
       'sent_time', 'setfieldval', 'show', 'show2', 'show_indent',
       'show_summary', 'sniffed_on', 'sprintf', 'summary', 'time',
       'underlayer', 'upper_bonds']
    """

    @staticmethod
    def respond_tcp(packet):
        if not packet.payload.load == CONST.initiator_string:
            return

        ip_src=None
        ip_dst=None
        tcp_sport=None
        tcp_dport=None
        if 'IP' in packet:
            ip_src=packet['IP'].src
            ip_dst=packet['IP'].dst
        if 'TCP' in packet:
            tcp_sport=packet['TCP'].sport
            tcp_dport=packet['TCP'].dport

        send(
            IP(dst=ip_src, src=ip_dst)
            /TCP(dport=tcp_sport, sport=tcp_dport)
            /Raw(load=CONST.responder_string) )

        # create a packet
        # send it back to the originator of this packet

    @staticmethod
    def return_printable(packet):
        import pdb; pdb.set_trace()
        return "Packet {0} ==> {1}: {2}".format(
            packet[0][1].src, packet[0][1].dst, packet.payload.load)


def send_and_listen(
        destination_ip=None,
        destination_port=None,
        protocol=None):

    resp = sr(
        IP(dst=destination_ip)
        /(TCP(dport=destination_port) if protocol == 'TCP' else UDP(dport=destination_port))
        /Raw(load=CONST.initiator_string)
    )

    return resp

def listen(
        port=None,
        protocol=None,
        interface=None,
        reaction=None,
        bpf_override=None):
    """
    bpf_override is a string that adheres to the Berkeley Packet Filter syntax
    (http://biot.com/capstats/bpf.html)
    default bpf is 'ip dst port {port}'
    """

    bpf = (
        bpf_override
        or "{interface} {protocol} {port}".format(
            interface = interface or "",
            protocol=protocol or "",
            port="dst port {0}".format(port)
            )
        )
    bpf = bpf.strip()
    ## Setup sniff, filtering for IP traffic
    #scapy_all.sniff(filter="ip",prn=customAction)
    sniff(filter=bpf, prn=reaction)
