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
import urllib.request

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


def signal_handler(_sig, _frame):
    """Handle SIGINT cleanly."""
    print('\nSignal interrupt. Exiting.')
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

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
                with urllib.request.urlopen(self.api_url + 'status'):
                    self.logger.info('API connection established.')
                    break
            except (urllib.error.URLError, ConnectionRefusedError, ConnectionResetError):
                self.logger.warning('Could not connect to API at %s. Retrying..', self.api_url)
                time.sleep(self.params.api_retry)

        self.client_id = 'user'
        self.token = False
        self.get_jwt_token()

        if not self.token:
            self.logger.error('No authentication token. Exiting.')
            sys.exit()

    def do_request(self, path, method, data=None):
        """
        Make an HTTP request to the API.

        An error from one of the HTTP requests means the API server or the link
        to it has gone down. The easiest way to handle this is to exit() and let
        Docker restart the node container, or let the init system restart the
        script, allowing __init__() to run again and wait indefinitely for the
        server to come back up.
        """
        request = urllib.request.Request(
            self.api_url + path, data, method=method,
            headers={"Content-Type": "application/json", 'Authorization': self.token}
        )

        try:
            with urllib.request.urlopen(request) as resp:
                return resp.status
        except urllib.error.URLError as err:
            self.logger.error('URLError: %s: %s', request.full_url, err.reason)
        except ConnectionRefusedError as err:
            self.logger.error('ConnectionRefusedError: %s: %s', request.full_url, err)

        self.logger.error('Cannot reach API server. Exiting.')
        sys.exit()

    def get_jwt_token(self):
        """Get the JWT authentication token."""
        self.logger.info('Getting JWT token.')

        post_data = {
            "Content-Type": "application/json",
            'client_id': self.client_id,
            'client_secret': scrypt(str.encode(self.params.api_key),
                                    salt=str.encode(self.client_id),
                                    n=2**14, r=8, p=1, dklen=32).hex()
        }

        req = urllib.request.Request(
            self.api_url + 'auth', headers=post_data, method='POST')

        try:
            with urllib.request.urlopen(req) as resp:
                response_body = json.loads(resp.read().decode('utf-8'))
                self.token = f"{response_body['type']} {response_body['access_token']}"
        except urllib.error.HTTPError as err:
            self.logger.error('Error authenticating: %s', err)

    def add_hosts(self, short_id, hostnames):
        """Add hosts via API /add."""
        post_data = json.dumps({'short_id': short_id,
                                'hostnames': hostnames}).encode()

        req_status = self.do_request('add', 'POST', post_data)

        if req_status == 200:
            self.logger.info('Added: %s', ', '.join(hostnames))
        else:
            self.logger.error('Could not add hosts: %s: %s', short_id, req_status)

    def del_hosts(self, short_id):
        """Delete hosts with matching comment via API /del/."""
        req_status = self.do_request('del/' + short_id, 'DELETE')

        if req_status == 204:
            self.logger.info('Deleted: %s', short_id)
        else:
            self.logger.error('Could not delete hosts: %s: %s', short_id, req_status)


class DockerHandler():
    """Handle connecting to the Docker socket and the data it produces."""

    client = None

    def __init__(self, hosts_handler, **kwargs):
        """Initialize variables, do nothing until start_monitor()."""
        self.params = SimpleNamespace(**kwargs)
        self.logger = get_logger(self.__class__.__name__, self.params.log_level)
        self.hosts_handler = hosts_handler
        self.scan_success = False
        self.swarm_mode = False

        if self.params.ready_fd == '':
            self.ready_fd = False
        else:
            self.ready_fd = int(self.params.ready_fd)

    def get_client(self):
        """Create the Docker client object."""
        self.logger.debug('docker socket: %s', self.params.docker_socket)
        try:
            self.client = docker.DockerClient(base_url=self.params.docker_socket)
        except docker.errors.DockerException as err:
            self.logger.error('Could not open Docker socket. Halting.')
            self.logger.debug('Error: %s', err)
            sys.exit(1)
        else:
            self.logger.info('Connected to Docker socket.')
            if self.client.swarm.attrs:
                self.swarm_mode = True
                self.logger.info('Swarm mode detected.')

    @classmethod
    def get_hostnames(cls, container, get_extra_hosts=True):
        """Return a list of hostnames for a container."""
        hostnames = [container.attrs['Config']['Hostname']]
        labels = container.labels

        try:
            hostnames.append(labels['dnsmasq.updater.host'])
        except KeyError:
            pass

        pattern = re.compile(r'Host\(`([^`]*)`\)')

        for key, value in labels.items():
            if key.startswith('traefik.http.routers.'):
                for match in pattern.finditer(value):
                    hostnames.append(match.group(1))

        if get_extra_hosts:
            extra_hosts = container.attrs['HostConfig']['ExtraHosts']
            if extra_hosts:
                hostnames = hostnames + extra_hosts

        return hostnames

    def scan_runnning_containers(self):
        """Scan running containers, find any with dnsmasq.updater.enable."""
        self.logger.info('Started scanning running containers.')

        if self.swarm_mode:
            services = self.client.services.list(filters={"label": "dnsmasq.updater.enable"})
            for service in services:
                names = service.attrs['Spec']['Labels']['dnsmasq.updater.host'].split()
                self.logger.info('Found %s: %s', service.name, ', '.join(names))
                if self.hosts_handler.add_hosts(service.short_id, names):
                    self.scan_success = True

        else:
            containers = self.client.containers.list(
                filters={"label": "dnsmasq.updater.enable", "status": "running"})
            for container in containers:
                names = self.get_hostnames(container)
                self.logger.info('Found %s: %s', container.name, ', '.join(names))
                if self.hosts_handler.add_hosts(container.short_id, names):
                    self.scan_success = True

        self.logger.info('Finished scanning running containers.')

    def scan_network_containers(self):
        """Scan all containers on a specified network."""
        if self.swarm_mode:
            self.logger.info('Skipped network scan in swarm mode.')
            return

        self.logger.info('Started scanning containers on \'%s\' network.', self.params.network)

        try:
            network = self.client.networks.get(self.params.network)
        except docker.errors.NotFound:
            self.logger.error(
                'Cannot scan network: network \'%s\' does not exist.', self.params.network)
            return

        for container in network.containers:
            names = self.get_hostnames(container)
            self.logger.info('Found %s: %s', container.name, ', '.join(names))
            if self.hosts_handler.add_hosts(container.short_id, names):
                self.scan_success = True

        self.logger.info('Finished scanning containers on \'%s\' network.', self.params.network)

    def handle_container_event(self, event):
        """Handle a container event."""
        if self.swarm_mode:
            short_id = event['Actor']['Attributes']['com.docker.swarm.service.id'][:10]
            service = self.client.services.get(short_id)
            if 'dnsmasq.updater.enable' not in service.attrs['Spec']['Labels']:
                self.logger.debug('dnsmasq.updater.enable not found for %s', service.name)
                return
            # container = self.client.containers.get(event['Actor']['ID'])
            name = service.name
            names = service.attrs['Spec']['Labels']['dnsmasq.updater.host'].split()
        else:
            if 'dnsmasq.updater.enable' not in event['Actor']['Attributes']:
                return
            container = self.client.containers.get(event['Actor']['ID'])
            short_id = container.short_id
            name = container.name
            names = self.get_hostnames(container)

        if event['status'] == 'start':
            event_verb = 'starting'
        elif event['status'] == 'stop':
            event_verb = 'stopping'

        self.logger.info('Detected %s %s.', name, event_verb)

        if event['status'] == 'start':
            self.hosts_handler.add_hosts(short_id, names)
        elif event['status'] == 'stop':
            self.hosts_handler.del_hosts(short_id)

    def handle_network_event(self, event):
        """Handle a network event."""
        try:
            container = self.client.containers.get(event['Actor']['Attributes']['container'])
        except docker.errors.NotFound:
            self.logger.warning(
                'Container %s not found.', event['Actor']['Attributes']['container'])
            container = None

        if container is not None:
            network = event['Actor']['Attributes']['name']

            if event['Action'] == 'connect':
                event_verb = 'connecting to'
            elif event['Action'] == 'disconnect':
                event_verb = 'disconnecting from'

            if self.swarm_mode:
                short_id = container.labels['com.docker.swarm.service.id'][:10]
                service = self.client.services.get(short_id)
                name = service.name
                names = service.attrs['Spec']['Labels']['dnsmasq.updater.host'].split()
            else:
                short_id = container.short_id
                name = container.name
                names = self.get_hostnames(container)

            self.logger.info(
                'Detected %s %s \'%s\' network.', name, event_verb, network)

            if event['Action'] == 'connect':
                self.hosts_handler.add_hosts(short_id, names)
            elif event['Action'] == 'disconnect':
                self.hosts_handler.del_hosts(short_id)

    def handle_events(self, event):
        """Monitor the docker socket for events."""
        # if (event['Type'] == 'service'):
        #     self.logger.debug('Service event: %s', event)
        # elif (event['Type'] == 'container'):
        #     self.logger.debug('Container event: %s', event)
        # elif (event['Type'] == 'network'):
        #     self.logger.debug('Network event: %s', event)

        # trigger on container start/stop
        if (event['Type'] == 'container') and (event['status'] in {'start', 'stop'}):
            self.handle_container_event(event)

        # trigger on network connect/disconnect
        elif (event['Type'] == 'network') and \
            (self.params.network in event['Actor']['Attributes']['name']) \
                and (event['Action'] in {'connect', 'disconnect'}):
            self.handle_network_event(event)

    def start_monitor(self):
        """
        Connect to Docker socket.

        Process existing containers then monitor events.
        """
        self.get_client()
        self.scan_runnning_containers()

        if self.params.network:
            self.scan_network_containers()

        # if self.scan_success:
        #     self.hosts_handler.queue_write()

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
            'api_server': '',
            'api_port': '8080',
            'api_key': '',
            'api_retry': 10,
            'log_level': self.log_level,
            'ready_fd': ''
        }

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

        self.logger.debug('Initial args: %s',
                          json.dumps(vars(self.args), indent=4))

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
                self.defaults.update(dict(config.items("api")))

                self.logger.debug('Args from config file: %s', json.dumps(self.defaults, indent=4))
            else:
                self.logger.error('Config file (%s) does not exist.',
                                  self.args.config_file)

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
        api_group = parser.add_argument_group(title='API')

        docker_group.add_argument(
            '-D', '--docker_socket', action='store', metavar='SOCKET',
            help='path to the docker socket (default: \'%(default)s\')')
        docker_group.add_argument(
            '-n', '--network', action='store', metavar='NETWORK',
            help='Docker network to monitor')
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
            help='delay in seconds before retrying failed connection (default: \'%(default)s\')')
        parser.add_argument(
            '--ready_fd', action='store', metavar='INT',
            help='set to an integer to enable signalling readiness by writing '
            'a new line to that integer file descriptor')

        self.args = parser.parse_args()

        self.logger.debug('Parsed command line:\n%s',
                          json.dumps(vars(self.args), indent=4))

    def check_args(self):
        """Check we have all the information we need to run."""
        if self.args.api_key == '':
            self.logger.error('No API key specified.')
            sys.exit(1)

        if self.args.api_server == '':
            self.logger.error('No API server specified.')
            sys.exit(1)

    def get_args(self):
        """Return all config parameters."""
        return self.args


def main():
    """Do all the things."""
    config = ConfigHandler()
    args = config.get_args()

    hosts_handler = APIClientHandler(**vars(args))
    data_handler = DockerHandler(hosts_handler, **vars(args))

    try:
        data_handler.start_monitor()
    except SystemExit:
        pass


if __name__ == '__main__':
    main()
