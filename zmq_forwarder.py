import win32service
import servicemanager
import socket
import win32serviceutil
import zmq

# Note that this service can't stop.

SUB_PORT = 5559
PUB_PORT = 5560


class AppServerSvc(win32serviceutil.ServiceFramework):
    _svc_name_ = "ZMQForwarder"
    _svc_display_name_ = "ZeroMQ Forwarder Service"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        socket.setdefaulttimeout(60)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        forwarder()


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
    win32serviceutil.HandleCommandLine(AppServerSvc)
