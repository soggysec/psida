import os
import json
from socket import gethostbyname
import traceback
import ida_diskio

CONFIG_FILE_NAME = os.path.join(os.path.expandvars(ida_diskio.get_user_idadir()), r'idb_push.cfg')

USER = 'user'
BACKEND_HOSTNAME = 'backend_hostname'
SUB_PORT = 'sub_port'
PUB_PORT = 'pub_port'
ZMQ_TIMEOUT_MS = 'timeout'
MAX_ITEMS_IN_LIST = 'max_items'
DEBUG = 'debug'
ZMQ_CONNECTIVITY_TEST_TIMEOUT_MS = 'connectivity_test_timeout'

# filled with reasonable defaults
CONFIGURATION = {
    USER: os.getenv('COMPUTERNAME'),
    BACKEND_HOSTNAME: '',
    SUB_PORT: 5560,
    PUB_PORT: 5559,
    ZMQ_TIMEOUT_MS: 100,
    ZMQ_CONNECTIVITY_TEST_TIMEOUT_MS: 1000,
    MAX_ITEMS_IN_LIST: 1000,
    DEBUG: False
}


def store_configuration():
    with open(CONFIG_FILE_NAME, 'w') as f:
        json.dump(CONFIGURATION, f)


def load_configuration():
    global CONFIGURATION

    with open(CONFIG_FILE_NAME) as f:
        loaded_config = json.load(f)
    for key in loaded_config:
        CONFIGURATION[key] = loaded_config[key]


def configure(backend_hostname=None,
              pub_port=None,
              sub_port=None,
              timeout=None,
              connectivity_test_timeout=None,
              max_items=None,
              user=None,
              debug=None):
    global CONFIGURATION

    # Try resolving the backend_hostname to IPv4.
    # 'gethostbyname' only supports IPv4, which is nice.
    # If the given string is an IP address, 'gethostbyname' returns it, which is also nice.
    if backend_hostname:
        backend_hostname = gethostbyname(backend_hostname)

    # since this is a dictionary, all the arguments
    # that are None will overwrite one another -
    # and we don't mind at all
    arguments_to_names = {backend_hostname: BACKEND_HOSTNAME,
                          pub_port: PUB_PORT,
                          sub_port: SUB_PORT,
                          timeout: ZMQ_TIMEOUT_MS,
                          connectivity_test_timeout: ZMQ_CONNECTIVITY_TEST_TIMEOUT_MS,
                          max_items: MAX_ITEMS_IN_LIST,
                          user: USER,
                          debug: DEBUG}

    for (argument, name) in arguments_to_names.iteritems():
        if argument is None:
            continue
        CONFIGURATION[name] = argument

    store_configuration()


def set_configuration():
    # load from the configuration file -
    # and create it if necessary
    try:
        if os.path.isfile(CONFIG_FILE_NAME):
            # read from the configuration file
            "loading configuration"
            load_configuration()
        else:
            # create a configuration file
            # with default values
            store_configuration()

    except:
        print 'ERROR - Configuration - Couldn\'t load or create the configuration file'
        if CONFIGURATION['debug']:
            traceback.print_exc()


set_configuration()
