from wsgiref.util import setup_testing_defaults
from wsgiref.simple_server import make_server
from time import sleep
import threading

class CONST(object):
    agent_response='agent-smith-response'

def simple_app(environ, start_response):
    """
    Respond to a GET with a 200 and the known agent_response string.
    """

    setup_testing_defaults(environ)
    status = '200 OK'
    headers = [('Content-type', 'text/plain')]
    start_response(status, headers)
    return CONST.agent_response

def _server_killer(httpd=None, timeout=None):
    """
    Used to kill the server daemon after a given timeout.  Does not run if
    timeout not provided.
    """
    if timeout:
     sleep(timeout)
     httpd.shutdown()

def start_server(port, timeout=None):
    """
    Create and start a wsgiref server daemon.
    Initialize a thread to kill the server daemon after 'timeout' seconds
    if timeout is provided.
    """

    # Create the simple server
    httpd = make_server('', port, simple_app)

    # Start the thread that will kill the server after timeout seconds
    threading.Thread(
        target=_server_killer,
        kwargs={'httpd':httpd, 'timeout':timeout}).start()

    # Start the server
    httpd.serve_forever()

def get_and_check(destination, port):
    """
    Send a GET request to 'destination' at 'port'.
    If a positive response is detected, return True.
    """
    import urllib2
    import sys
    url ="http://{destination}:{port}".format(
        destination=destination, port=port)

    response = urllib2.urlopen(url)
    html = response.read()

    if html == CONST.agent_response:
        return True
    return False
