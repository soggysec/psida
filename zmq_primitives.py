import pprint
import random
import time
import idb_push_config
reload(idb_push_config)
from idb_push_ops import *

try:
    import zmq
except ImportError:
    print 'WARNING - zmq_primitives.py - zmq not found, idb_push will not function properly'
    zmq = None

CONNECTION_STRING_FORMAT = r'tcp://%s:%d'


class ZMQConnectionException(BaseException):
    pass


def zmq_assert_imported():
    assert zmq is not None, "ERROR - zmq_test_connectivity - zmq not imported"


def zmq_test_connectivity(backend=CONFIGURATION[BACKEND_HOSTNAME],
                          pub_port=CONFIGURATION[PUB_PORT],
                          sub_port=CONFIGURATION[SUB_PORT],
                          timeout_ms=CONFIGURATION[ZMQ_TIMEOUT_MS]):
    """Creates a temporary ZMQ socket and tests server connectivity"""
    zmq_assert_imported()

    pub_connection_string = r"tcp://%s:%d" % (backend,
                                              pub_port)
    sub_connection_string = r"tcp://%s:%d" % (backend,
                                              sub_port)
    context = zmq.Context()
    random.seed()

    rx_end_time = time.time() + (timeout_ms / 1000.0)
    found_random_string = False

    while time.time() < rx_end_time:
        try:
            # open a transmitting socket
            tx_socket = context.socket(zmq.PUB)
            tx_socket.setsockopt(zmq.LINGER, timeout_ms)
            tx_socket.connect(pub_connection_string)
            topic = "0"  # dummy

            # open a receiving socket
            rx_socket = context.socket(zmq.SUB)
            rx_socket.connect(sub_connection_string)
            rx_socket.setsockopt(zmq.SUBSCRIBE, "")
            rx_socket.RCVTIMEO = timeout_ms

            # sleep to allow both sockets to connect
            time.sleep(timeout_ms / 1000.0)

            # send a random test packet
            random_string = "%010x" % random.randrange(16 ** 10)
            tx_socket.send_multipart([topic, json.dumps(random_string)])

            # wait for a while for the reply to arrive
            _, message = rx_socket.recv_multipart()
            tx_socket.close()
            rx_socket.close()

            if random_string in message:
                found_random_string = True
                break

        except zmq.error.Again:
            # timeout - that's OK
            continue

    if not found_random_string:
        raise ZMQConnectionException('ZMQ connectivity test failed!')


def zmq_open_sub_socket(backend=CONFIGURATION[BACKEND_HOSTNAME],
                        sub_port=CONFIGURATION[SUB_PORT],
                        timeout_ms=CONFIGURATION[ZMQ_TIMEOUT_MS],
                        debug=CONFIGURATION[DEBUG]):
    zmq_assert_imported()
    try:
        context = zmq.Context()
        zmq_socket = context.socket(zmq.SUB)
        zmq_socket.setsockopt(zmq.SUBSCRIBE, '')
        zmq_socket.RCVTIMEO = timeout_ms

        connection_string = CONNECTION_STRING_FORMAT % (backend,
                                                        sub_port)
        zmq_socket.connect(connection_string)
        return zmq_socket

    except zmq.ZMQBaseError:
        if debug:
            traceback.print_exc()
        raise ZMQConnectionException('ERROR -  zmq_open_sub_socket')


def zmq_open_pub_socket(backend=CONFIGURATION[BACKEND_HOSTNAME],
                        pub_port=CONFIGURATION[PUB_PORT],
                        timeout_ms=CONFIGURATION[ZMQ_TIMEOUT_MS],
                        debug=CONFIGURATION[DEBUG]):
    zmq_assert_imported()
    try:
        context = zmq.Context()
        zmq_socket = context.socket(zmq.PUB)
        zmq_socket.setsockopt(zmq.LINGER, timeout_ms)

        connection_string = CONNECTION_STRING_FORMAT % (backend,
                                                        pub_port)
        zmq_socket.connect(connection_string)
        return zmq_socket

    except zmq.ZMQBaseError:
        if debug:
            traceback.print_exc()
        raise ZMQConnectionException('Error in creating ZMQ socket')


def zmq_send_json(zmq_socket,
                  json_message,
                  debug=CONFIGURATION[DEBUG]):
    zmq_assert_imported()
    try:
        topic = '0'  # dummy
        zmq_socket.send_multipart([topic, json.dumps(json_message)])

        if debug:
            print 'DEBUG - zmq_send_json - Sent message\r\n%s' % pprint.pformat(json_message)

    except zmq.ZMQBaseError:
        if debug:
            traceback.print_exc()
        raise Exception('Error in sending message in ZMQ socket')
