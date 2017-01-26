import argparse
from smith import api


class Command(object):
    def __init__(self, args):
        self.args = args
        self.run()

    def run(self):
        raise NotImplemented


class smith_ping(Command):
    def run(self):
        r = api.ping(
                self.args.port,
                self.args.destination,
                self.args.protocol,
                self.args.timeout)
        print 'success' if r else 'failure'
        exit(0 if r else 1)


class smith_listen(Command):
    def run(self):
        api.listen(self.args.port, self.args.protocol)


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
        choices=api.PROTOCOLS,
        help="Protocol to use to contact the remote agent.  TCP and UDP use raw "
             "sockets which will bypass IPTABLES rules.",
    )
    ping_parser.add_argument(
        '-t', '--timeout', default=10, type=int, help="Seconds to wait for response from server before giving up. Zero means 'wait forever'")
    ping_parser.set_defaults(func=smith_ping)

    listen_parser = subparsers.add_parser(
        "listen", usage="\n Server-side: listen for incoming ping requests from remote client.")
    listen_parser.add_argument(
        "port", type=int, help="The port the remote client is pinging")
    listen_parser.add_argument(
        "protocol",
        type=str,
        choices=api.PROTOCOLS,
        help=(
            "Protocol to use to contact the remote agent."
             "TCP and UDP use raw sockets which will bypass IPTABLES rules."))
    listen_parser.set_defaults(func=smith_listen)

    args = parser.parse_args()
    args.func(args)
