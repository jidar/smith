import argparse

class Command(object):
    def __init__(self, args):
        self.args = args
        self.run()

    def run(self):
        raise NotImplemented

class ping_remote_agent(Command):
    def run(self):
        if self.args.protocol == "REST":
            import simpleserver
            r = simpleserver.get_and_check(
                self.args.destination,
                self.args.port)
            print "success" if r else "failure"
        else:
            import scapy_wrapper
            resp = scapy_wrapper.send_and_listen(
                destination_ip=self.args.destination,
                destination_port=self.args.port,
                protocol=self.args.protocol,
                timeout=self.args.timeout)

class init_server_agent(Command):
    def run(self):
        import scapy_wrapper
        reaction = None

        #This is a temp hack, i'm going to build a dispatcher with more methods,
        #and also a real respond method instead of the protocol specific one.
        if self.args.responder == 'TCP':
            import scapy_wrapper
            scapy_wrapper.listen(
                port=self.args.port,
                reaction=scapy_wrapper.Reactions.respond_tcp)
        elif self.args.responder == 'UDP':
            import scapy_wrapper
            scapy_wrapper.listen(
                port=self.args.port,
                reaction=scapy_wrapper.Reactions.respond_udp)
        elif self.args.responder == 'REST':
            import simpleserver
            simpleserver.start_server(self.args.port)
        else:
            print "Unsupported responder type"
            exit()


def cli():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(metavar="ping, listen")

    ping_parser = subparsers.add_parser(
        "ping", usage="\n  Initiate a port-specific ping against a listening agent")
    ping_parser.add_argument(
        "port", type=int, help="The port the remote agent is listening on")
    ping_parser.add_argument(
        "destination", type=str, help="IPv4 address of the server the remote agent is listening on")
    ping_parser.add_argument(
        "protocol",
        type=str,
        choices=["TCP","UDP","REST"],
        help="Protocol to use to contact the remote agent.  TCP and UDP use raw "
             "sockets which will bypass IPTABLES rules.",
    )
    ping_parser.add_argument(
        '-t', '--timeout', default=0, type=int, help="Seconds to wait for response from server before giving up. Zero means 'wait forever'")
    ping_parser.set_defaults(func=ping_remote_agent)

    listen_parser = subparsers.add_parser(
        "listen", usage="\n Server-side: listen for incoming ping requests from remote client.")
    listen_parser.add_argument(
        "port", type=int, help="The port the remote client is pinging")
    listen_parser.add_argument(
        "responder",
        type=str,
        choices=["TCP","UDP","REST"],
        help=(
            "Protocol to use to contact the remote agent."
             "TCP and UDP use raw sockets which will bypass IPTABLES rules."))
    listen_parser.set_defaults(func=init_server_agent)

    args = parser.parse_args()
    args.func(args)
