import argparse

PROTOCOLS = ['udp', 'tcp', 'rest']

def ping(port, destination, protocol, timeout=10):
    resp = None
    if protocol == "rest":
        import wsgiref_wrapper
        resp = wsgiref_wrapper.get_and_check(destination, port)
        return True if resp else False
    else:
        import scapy_wrapper
        resp = scapy_wrapper.send_and_listen(
            destination_ip=destination,
            destination_port=port,
            protocol=protocol,
            timeout=timeout)
        #TODO: Make this check better
        try:
            if resp[0].res:
                return True
        except IndexError:
            return False


def listen(port, protocol):
    if protocol == 'tcp':
        import scapy_wrapper
        scapy_wrapper.listen(
            port=port,
            protocol=protocol,
            reaction=scapy_wrapper.Reactions.respond_tcp)
    elif protocol == 'udp':
        import scapy_wrapper
        scapy_wrapper.listen(
            port=port,
            protocol=protocol,
            reaction=scapy_wrapper.Reactions.respond_udp)
    elif protocol == 'rest':
        import wsgiref_wrapper
        wsgiref_wrapper.start_server(port)
    else:
        raise Exception("Unsupported protocol type")
