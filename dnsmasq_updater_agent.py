#!/usr/bin/env python3

"""
Docker Dnsmasq Updater.

Use the Docker socket to update remote dnsmasq server with container hostnames
"""

import os
import sys
import signal
import logging
import argparse
import configparser
import json
import time
import re
import socket
import urllib.request

from threading import Timer
from types import SimpleNamespace
from typing import Dict

from hashlib import scrypt

import docker  # type: ignore[import-untyped]

# config file and list of paths, in the order to try
CONFIG_FILE = 'dnsmasq_updater_agent.conf'
CONFIG_PATHS = [os.path.dirname(os.path.realpath(__file__)), '/etc/', '/conf/']

DEFAULT_LOG_LEVEL = logging.INFO


class Formatter(logging.Formatter):
    """Format logger output."""

    def formatTime(self, record, datefmt=None):
        """Use system timezone and add milliseconds."""
        datefmt = f'%Y-%m-%d %H:%M:%S.{round(record.msecs):03d} ' + time.strftime('%z')
        return time.strftime(datefmt, self.converter(record.created))


STDOUT_HANDLER = logging.StreamHandler(sys.stdout)
STDOUT_HANDLER.setFormatter(
    Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))


def signal_handler(sig, _frame):
    """Handle SIGINT cleanly."""
    print('\nCaught signal:', sig, '\n')
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

loggers: Dict[str, str] = {}


def get_logger(class_name, log_level):
    """Get logger objects for individual classes."""
    name = os.path.splitext(os.path.basename(__file__))[0]
    if log_level == logging.DEBUG:
        name = '.'.join([name, class_name])

    if loggers.get(name):
        return loggers.get(name)

    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.addHandler(STDOUT_HANDLER)
    logger.setLevel(log_level)

    loggers[name] = logger
    return logger


class ResettableTimer():
    """A resettable timer class."""

    def __init__(self, delay, function):
        """Initialize timing."""
        self._running = False
        self._delay = delay
        self._function = function
        self._timer = Timer(self._delay, self._function)

    def __set(self):
        self._timer = Timer(self._delay, self._function)

    def start(self):
        """If not running, start timer."""
        if not self._running:
            self.__set()
            self._timer.daemon = True
            self._timer.start()
            self._running = True

    def cancel(self):
        """If running, cancel timer."""
        if self._running:
            self._timer.cancel()
            self._running = False

    def reset(self):
        """Reset timer."""
        self.cancel()
        self.start()


class APIClientHandler():
    """
    Feed hosts data directly to the API.

    status with GET to <api_url>/status
    add hosts with POST to <api_url>/add
    delete hosts with DELETE to <api_url>/del/<short_id>
    """

    def __init__(self, **kwargs):
        """Initialize."""
        self.params = SimpleNamespace(**kwargs)
        self.logger = get_logger(self.__class__.__name__, self.params.log_level)
        self.api_url = 'http://' + self.params.api_server + ':' + self.params.api_port + '/'

        while True:
            try:
                with urllib.request.urlopen(self.api_url + 'status') as resp:
                    self.api_instance = resp.getheader('DMU-API-ID')
                    self.logger.info('API connection established.')
                    break
            except (urllib.error.URLError, ConnectionRefusedError, ConnectionResetError):
                self.logger.warning('Could not connect to API at %s. Retrying in %s seconds..',
                                    self.api_url, self.params.api_retry)
                time.sleep(self.params.api_retry)

        self.client_id = 'user'
        self.token = False

        self.get_jwt_token()
        if not self.token:
            self.logger.error('No authentication token. Exiting.')
            sys.exit(1)

        self.logger.debug('Starting status check timer.')
        self.status_timer = ResettableTimer(self.params.api_check, self.check_status)
        self.status_timer.start()

    def get_jwt_token(self):
        """Get the JWT authentication token."""
        self.logger.info('Getting JWT token.')

        header_data = {
            "Content-Type": "application/json",
            'clientId': self.client_id,
            'clientSecret': scrypt(str.encode(self.params.api_key),
                                   salt=str.encode(self.client_id),
                                   n=2**14, r=8, p=1, dklen=32).hex()
        }
        req = urllib.request.Request(
            self.api_url + 'auth', headers=header_data, method='POST')

        try:
            with urllib.request.urlopen(req) as resp:
                response_body = json.loads(resp.read().decode('utf-8'))
                self.token = f"{response_body['type']} {response_body['access_token']}"
        except (urllib.error.HTTPError, json.decoder.JSONDecodeError) as err:
            self.logger.error('Error authenticating: %s', err)

    def do_request(self, path, method='GET', data=None):
        """
        Make an HTTP request to the API.

        An error from one of the HTTP requests means the API server or the link
        to it has gone down. The easiest way to handle this is to exit() and let
        Docker restart the Agent container, or let the init system restart the
        script, allowing __init__() to run again and wait indefinitely for the
        server to come back up.

        Similarly, if the unique ID string from the API changes, assume the
        manager has restarted and won't have the full data set so an exit() is
        warranted.
        """
        request = urllib.request.Request(
            self.api_url + path, data, method=method,
            headers={"Content-Type": "application/json", 'Authorization': self.token}
        )

        try:
            with urllib.request.urlopen(request) as resp:
                if resp.getheader('DMU-API-ID') == self.api_instance:
                    self.status_timer.reset()
                    return resp.status
                self.logger.warning('The API identification string has changed.')

        except urllib.error.URLError as err:
            self.logger.error('URLError: %s: %s', request.full_url, err.reason)
        except ConnectionRefusedError as err:
            self.logger.error('ConnectionRefusedError: %s: %s', request.full_url, err)

        self.logger.error('Lost connection to API. Exiting.')
        self.params.clean_on_exit = False

        os.kill(os.getpid(), signal.SIGINT)
        sys.exit(0)

    def add_hosts(self, container_data):
        """
        Add hosts via API /add.

        Hostnames may include an IP address to override the manager's default
        address, in the form '<hostname>:<address>'.

        Accepts a container_data dictionary.
        """
        if container_data['hostnames'] is None:
            self.logger.debug('add_hosts: nothing to add')

        else:
            post_data = json.dumps({'short_id': container_data['id'],
                                    'hostnames': container_data['hostnames'],
                                    'from': self.params.this_host})

            self.logger.debug('add_hosts: %s', post_data)
            req_status = self.do_request('add', 'POST', post_data.encode())

            if req_status == 200:
                self.logger.info('Added: %s', ', '.join(container_data['hostnames']))
            else:
                self.logger.error('Could not add hosts: %s: %s', req_status, container_data['id'])

    def del_hosts(self, short_id):
        """
        Delete hosts with matching comment via API /del/.

        Accepts a container short_id string or a container_data dictionary.
        """
        if isinstance(short_id, dict):
            short_id = short_id['id']

        req_status = self.do_request('del/' + short_id, 'DELETE')

        if req_status == 204:
            self.logger.info('Deleted: %s', short_id)
        else:
            self.logger.error('Could not delete hosts: %s: %s', req_status, short_id)

    def clean_hosts(self):
        """
        Delete all hosts for this node when exiting.

        This assumes the services go down when this Agent goes down, which isn't
        necearrily true but since, at the moment, the manager doesn't do any
        garbage collection of its own we're better off erring on the side of
        removing working hostnames over preserving non-working hostnames.
        """
        if self.params.clean_on_exit:
            self.logger.info('Cleaning hosts.')
            self.del_hosts(self.params.this_host)

    def check_status(self):
        """
        Check the status of the API on a timer.

        We don't actually need to process the response. If the API is down or
        the instance ID has changed it will be caught and handled by do_request().
        The fact we're repeating this action on a timer is the important thing.
        """
        self.do_request('status')
        self.status_timer.reset()


class DockerHandler():
    """Handle connecting to the Docker socket and the data it produces."""

    client = None

    def __init__(self, hosts_handler, **kwargs):
        """Initialize variables, do nothing until start_monitor()."""
        self.params = SimpleNamespace(**kwargs)
        self.logger = get_logger(self.__class__.__name__, self.params.log_level)
        self.hosts_handler = hosts_handler
        # self.swarm_mode = False

        self.event_verbs = {'start': 'starting',
                            'stop': 'stopping',
                            'connect': 'connecting to',
                            'disconnect': 'disconnecting from'}

        self.get_client()
        self.docker_node_ip = socket.getaddrinfo(self.client.info()['Name'],
                                                 self.params.api_port,
                                                 proto=socket.IPPROTO_TCP)[0][4][0]

        self.logger.debug('Docker node: %s: %s',
                          self.client.info()['Name'], self.docker_node_ip)

        if self.params.ready_fd == '':
            self.ready_fd = False
        else:
            self.ready_fd = int(self.params.ready_fd)

    def get_client(self):
        """Create the Docker client object."""
        try:
            self.client = docker.DockerClient(base_url=self.params.docker_socket)
        except docker.errors.DockerException as err:
            self.logger.error('Could not open Docker socket at %s. Exiting.',
                              self.params.docker_socket)
            self.logger.debug('Error: %s', err)
            sys.exit(1)

        self.logger.info('Connected to Docker socket.')

        # currently not using self.swarm_mode, so this code may not be necessary
        # but it doesn't hurt to log the output anyway
        swarm_status = self.client.info()['Swarm']['LocalNodeState']
        match swarm_status:
            case 'inactive':
                self.logger.info('Docker standalone detected.')
            case 'active':
                if self.client.info()['Swarm']['ControlAvailable']:
                    self.logger.info('Docker Swarm manager detected.')
                    # self.swarm_mode = 'manager'
                else:
                    self.logger.info('Docker Swarm node detected.')
                    # self.swarm_mode = 'node'
            case _:
                self.logger.error('Standalone/Swarm detection failed: %s', swarm_status)
                sys.exit(1)

    def get_hostnames(self, container):
        """
        Return a list of hostnames for a container or service.

        Include any IP address override in the form '<hostname>:<address>'
        """
        try:
            hostnames = container.attrs['Spec']['TaskTemplate']['ContainerSpec']['Hostname'].split()
            labels = container.attrs['Spec']['Labels']
        except KeyError:
            hostnames = container.attrs['Config']['Hostname'].split()
            labels = container.labels

        try:
            hostnames.append(labels['dnsmasq.updater.host'])
        except KeyError:
            pass

        if self.params.labels_from is not None:
            traefik_pattern = re.compile(r'Host\(`([^`]*)`\)')
            for key, value in labels.items():
                if 'traefik' in self.params.labels_from and key.startswith('traefik.http.routers.'):
                    for match in traefik_pattern.finditer(value):
                        hostnames.append(match.group(1))

        ip = self.get_hostip(container)
        if ip is not None:
            hostnames = [x + ':' + ip for x in hostnames]

        try:
            extra_hosts = container.attrs['HostConfig']['ExtraHosts']
        except KeyError:
            pass
        else:
            if extra_hosts:
                hostnames = hostnames + extra_hosts

        return hostnames

    def get_hostip(self, container):
        """Get any IP address set with a label."""
        try:
            hostip = container.labels['dnsmasq.updater.ip']
        except (AttributeError, KeyError):
            return None

        if hostip == 'host':
            return self.docker_node_ip
        return hostip

    def get_container_data(self, container):
        """
        Put data we need into an dictionary.

        container_data =
            {'id': <short_id>, 'name': <container name>, 'hostnames': <hostnames>}
        """
        hostnames = self.get_hostnames(container)
        try:
            name = container.labels['com.docker.swarm.service.name']
        except (AttributeError, KeyError):
            name = container.name

        return {"id": container.short_id[:12], "name": name, "hostnames": hostnames}

    def scan_runnning_containers(self):
        """Scan running containers, find any with dnsmasq.updater.enable."""
        self.logger.info('Started scanning running containers.')

        try:
            containers = self.client.containers.list(
                filters={"label": "dnsmasq.updater.enable", "status": "running"})
        except docker.errors.APIError as err:
            self.logger.warning('Could not scan running containers: %s', err)
            return

        for container in containers:
            container_data = self.get_container_data(container)
            self.logger.info('Found %s: %s', container_data['name'],
                             ', '.join(container_data['hostnames']))
            self.hosts_handler.add_hosts(container_data)

        self.logger.info('Finished scanning running containers.')

    def scan_network_containers(self):
        """Scan all containers on a specified network."""
        self.logger.info('Started scanning containers on \'%s\' network.', self.params.network)

        try:
            network = self.client.networks.get(self.params.network)
        except docker.errors.NotFound:
            self.logger.error(
                'Cannot scan network: network \'%s\' does not exist.', self.params.network)
            return

        if network.attrs['Containers'] is not None:
            for container in network.attrs['Containers']:
                try:
                    this_container = self.client.containers.get(container)
                except docker.errors.NotFound:
                    continue

                container_data = self.get_container_data(this_container)

                # don't add self based on a network scan, since we're probably just
                # using the network for API communication as a convenience
                if self.params.this_host in container_data['hostnames']:
                    continue

                self.logger.info('Found %s: %s', container_data['name'],
                                 ', '.join(container_data['hostnames']))
                self.hosts_handler.add_hosts(container_data)

        self.logger.info('Finished scanning containers on \'%s\' network.', self.params.network)

    def handle_container_event(self, event):
        """Handle a container event."""
        container = self.client.containers.get(event['Actor']['ID'])

        if 'dnsmasq.updater.enable' not in container.labels:
            return

        container_data = self.get_container_data(container)

        self.logger.info('Detected %s %s.', container_data['name'],
                         self.event_verbs[event['status']])

        if event['status'] == 'stop':
            self.hosts_handler.del_hosts(container_data)
        elif event['status'] == 'start':
            self.hosts_handler.add_hosts(container_data)

    def handle_network_event(self, event):
        """Handle a network event."""
        try:
            container = self.client.containers.get(event['Actor']['Attributes']['container'])
        except docker.errors.NotFound:
            self.logger.error(
                'Container %s not found.', event['Actor']['Attributes']['container'])
            return

        container_data = self.get_container_data(container)

        if self.params.this_host in container_data['hostnames']:
            return

        self.logger.info('Detected %s %s \'%s\' network.', container_data['name'],
                         self.event_verbs[event['Action']],
                         event['Actor']['Attributes']['name'])

        if event['Action'] == 'disconnect':
            self.hosts_handler.del_hosts(container_data)
        elif event['Action'] == 'connect':
            self.hosts_handler.add_hosts(container_data)

    def handle_events(self, event):
        """Monitor the docker socket for relevant container and network events."""
        if (event['Type'] == 'container') and (event['status'] in {'start', 'stop'}):
            self.handle_container_event(event)

        elif (event['Type'] == 'network') \
            and (self.params.network in event['Actor']['Attributes']['name']) \
                and (event['Action'] in {'connect', 'disconnect'}):
            self.handle_network_event(event)

    def start_monitor(self):
        """
        Connect to Docker socket.

        Process existing containers then monitor events.
        """
        self.scan_runnning_containers()

        if self.params.network:
            self.scan_network_containers()

        if self.ready_fd:
            self.logger.info('Initialization done. Signalling readiness.')
            self.logger.debug(
                'Readiness signal writing to file descriptor %s.', self.ready_fd)
            try:
                os.write(self.ready_fd, '\n'.encode())
            except OSError:
                self.logger.warning('Could not signal file descriptor \'%s\'.', self.ready_fd)
        else:
            self.logger.info('Initialization done.')

        events = self.client.events(decode=True)

        while True:
            for event in events:
                self.handle_events(event)


class ConfigHandler():
    """Read config files and parse commandline arguments."""

    log_level = DEFAULT_LOG_LEVEL

    def __init__(self):
        """Initialize default config, parse config file and command line args."""
        self.defaults = {
            'config_file': CONFIG_FILE,
            'docker_socket': 'unix://var/run/docker.sock',
            'network': '',
            'labels_from': None,
            'api_server': '',
            'api_port': '8080',
            'api_key': '',
            'api_retry': 10,
            'api_check': 60,
            'log_level': self.log_level,
            'ready_fd': '',
            'clean_on_exit': True
        }

        try:
            self.defaults['this_host'] = os.environ['HOSTNAME']
        except KeyError:
            self.defaults['this_host'] = os.uname()[1]  # pylint: disable=no-member

        self.args = []
        self.config_parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=__doc__, add_help=False)

        self.parse_initial_config()
        self.parse_config_file()
        self.parse_command_line()
        self.check_args()

    def parse_initial_config(self):
        """Just enough argparse to specify a config file and a debug flag."""
        self.config_parser.add_argument(
            '-c', '--config_file', action='store', metavar='FILE',
            help='external configuration file')
        self.config_parser.add_argument(
            '--debug', action='store_true', help='turn on debug messaging')

        self.args = self.config_parser.parse_known_args()[0]

        if self.args.debug:
            self.log_level = logging.DEBUG
            self.defaults['log_level'] = logging.DEBUG

        self.logger = get_logger(self.__class__.__name__, self.log_level)
        self.logger.debug('Initial args: %s', json.dumps(vars(self.args), indent=4))

    def parse_config_file(self):
        """Find and read external configuration files, if they exist."""
        self.logger.debug('self.args.config_file: %s', self.args.config_file)

        # find external configuration if none is specified
        if self.args.config_file is None:
            for config_path in CONFIG_PATHS:
                config_file = os.path.join(config_path, CONFIG_FILE)
                self.logger.debug('Looking for config file: %s', config_file)
                if os.path.isfile(config_file):
                    self.logger.info('Found config file: %s', config_file)
                    self.args.config_file = config_file
                    break

        if self.args.config_file is None:
            self.logger.info('No config file found.')

        # read external configuration if specified and found
        if self.args.config_file is not None:
            if os.path.isfile(self.args.config_file):
                config = configparser.ConfigParser()
                config.read(self.args.config_file)
                self.defaults.update(dict(config.items("general")))
                self.defaults.update(dict(config.items("docker")))
                self.defaults.update(dict(config.items("dns")))
                self.defaults.update(dict(config.items("api")))

                self.logger.debug('Args from config file: %s', json.dumps(self.defaults, indent=4))
            else:
                self.logger.error('Config file (%s) does not exist.',
                                  self.args.config_file)

    @staticmethod
    def parse_commas(this_string):
        """Convert a comma separated string into a list variable."""
        if this_string:
            return this_string.split(',')
        return None

    def parse_command_line(self):
        """
        Parse command line arguments.

        Overwrite both default config and anything found in a config file.
        """
        parser = argparse.ArgumentParser(
            description='Docker Dnsmasq Updater Agent',
            parents=[self.config_parser])
        parser.set_defaults(**self.defaults)

        docker_group = parser.add_argument_group(title='Docker')
        docker_group.add_argument(
            '-D', '--docker_socket', action='store', metavar='SOCKET',
            help='path to the docker socket (default: \'%(default)s\')')
        docker_group.add_argument(
            '-n', '--network', action='store', metavar='NETWORK',
            help='Docker network to monitor')

        dns_group = parser.add_argument_group(title='DNS')
        dns_group.add_argument(
            '-L', '--labels_from', action='store', metavar='PROXIES', type=self.parse_commas,
            help='add hostnames from labels set by other services (default: \'%(default)s\')')

        api_group = parser.add_argument_group(title='API')
        api_group.add_argument(
            '-s', '--api_server', action='store', metavar='SERVER',
            help='API server address')
        api_group.add_argument(
            '-P', '--api_port', action='store', metavar='PORT',
            help='API server port (default: \'%(default)s\')')
        api_group.add_argument(
            '-k', '--api_key', action='store', metavar='KEY',
            help='API access key')
        api_group.add_argument(
            '-R', '--api_retry', action='store', metavar='SECONDS', type=int,
            help='delay before retrying failed connection (default: \'%(default)s\')')
        api_group.add_argument(
            '-t', '--api_check', action='store', metavar='SECONDS', type=int,
            help='delay between checking the API server status (default: \'%(default)s\')')
        api_group.add_argument(
            '--clean_on_exit', action=argparse.BooleanOptionalAction,
            help='delete this device\'s hosts from the API when the Agent shuts '
            'down (default: enabled)')
        parser.add_argument(
            '--ready_fd', action='store', metavar='INT',
            help='set to an integer to enable signalling readiness by writing '
            'a new line to that integer file descriptor')

        self.args = parser.parse_args()

        self.logger.debug('Parsed command line:\n%s',
                          json.dumps(vars(self.args), indent=4))

    def check_args(self):
        """Check we have all the information we need to run."""
        if self.args.api_server == '':
            self.logger.error('No API server specified.')
            sys.exit(1)

        if self.args.api_key == '':
            self.logger.error('No API key specified.')
            sys.exit(1)

    def get_args(self):
        """Return all config parameters."""
        return self.args


def main():
    """Do all the things."""
    config = ConfigHandler()
    args = vars(config.get_args())

    hosts_handler = APIClientHandler(**args)
    data_handler = DockerHandler(hosts_handler, **args)

    try:
        data_handler.start_monitor()
    except SystemExit:
        pass
    finally:
        if args['clean_on_exit'] is not None:
            hosts_handler.clean_hosts()
        hosts_handler.status_timer.cancel()
        print('Exiting.')


if __name__ == '__main__':
    main()
