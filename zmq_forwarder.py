#import win32service
#import servicemanager
#import win32serviceutil
import socket
import zmq

# Note that this service can't stop.

SUB_PORT = 5559
PUB_PORT = 5560


def forwarder():
    while True:
        try:
            context = zmq.Context()
            sub_socket = context.socket(zmq.SUB)
            sub_socket.bind("tcp://*:%d" % SUB_PORT)

            sub_socket.setsockopt(zmq.SUBSCRIBE, "")

            pub_socket = context.socket(zmq.PUB)
            pub_socket.bind("tcp://*:%d" % PUB_PORT)

            zmq.device(zmq.FORWARDER, sub_socket, pub_socket)

        # if it's a ZMQ error - do nothing, just reopen the device
        # otherwise we crash properly
        except zmq.ZMQBaseError:
            pass
        finally:
            sub_socket.close()
            pub_socket.close()
            context.term()


if __name__ == '__main__':
    forwarder()
