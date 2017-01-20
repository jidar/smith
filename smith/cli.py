import argparse
from common import *

class Command(object):
    def __init__(self, args):
        self.args = args
        self.run()
        print 'running'

    def run(self):
        raise NotImplemented

class ping(Command):
    def run(self):
        resp = send_and_listen(
            destination_ip=self.args.destination,
            destination_port=self.args.port,
            protocol=self.args.protocol)

class listencli(Command):
    def run(self):
        reaction = None
        if self.args.reaction == 'respond':
            #This is a temp hack, i'm going to build a dispatcher with more methods,
            #and also a real respond method instead of the protocol specific one.
            listen(port=self.args.port, reaction=Reactions.respond_tcp)


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
    ping_parser.set_defaults(func=ping)

    listen_parser = subparsers.add_parser(
        "listen", usage="\n Server-side: listen for incomming ping requests from remote client.")
    listen_parser.add_argument(
        "port", type=int, help="The port the remote client is pinging")
    listen_parser.add_argument(
        "reaction",
        type=str,
        choices=["respond","print", "log"],
        help="What you want the listener to do when it detects a packet.")
    listen_parser.set_defaults(func=listencli)

    args = parser.parse_args()
    args.func(args)

##OLDVVV
#
# # Registration subparsers
# register_parser = subparsers.add_parser(
#     "add", usage="\n  Add new venvs and commands to vcd")
# register_subparsers = register_parser.add_subparsers(metavar="venv, cmd")
#
# # register venv <name> <location>
# register_venv_sparser = register_subparsers.add_parser("venv")
# register_venv_sparser.add_argument(
#     'venv_alias', type=str, help="An alias used to address the virtualenv")
# register_venv_sparser.add_argument(
#     'path_to_venv_dir', type=str,
#     help="Location of the virtualenv top level directory")
# register_venv_sparser.set_defaults(func=register_venv)
#
# # register command <name> <location>
# register_venv_sparser = register_subparsers.add_parser("cmd")
# register_venv_sparser.add_argument(
#     'venv_alias', type=str, help="An alias used to address the virtualenv")
# register_venv_sparser.add_argument(
#     'command_alias', type=str,
#     help="An alias used to trigger the registered command.  The actual "
#     "command can be used here.")
# register_venv_sparser.add_argument(
#     'command', nargs='?', default='', type=str,
#     help="Optional.  If omitted, it is assumed that the command-alias is "
#     "the as the actual command")
# register_venv_sparser.set_defaults(func=register_cmd)
#
# # Listing subparsers
# list_parser = subparsers.add_parser(
#     "list", usage="\n  List registered venvs and commands")
# list_parser.add_argument(
#     'resource', type=str, choices=['venvs', 'cmds'], metavar="venvs, cmds")
# list_parser.set_defaults(func=list_resources)
#
# # source venv
# source_venv_parser = subparsers.add_parser("use", usage="\n Source a venv")
# source_venv_parser.add_argument(
#     'venv_alias', type=str, help="An alias used to address the virtualenv")
# source_venv_parser.set_defaults(func=source_venv)
