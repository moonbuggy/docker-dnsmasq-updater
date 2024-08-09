#!/usr/bin/env python3
# pylint: disable=too-many-lines
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
import subprocess
import socket
import ipaddress
import tempfile
import time
import re

from threading import Timer
from types import SimpleNamespace
from collections import defaultdict
from typing import Dict

from python_hosts import Hosts, HostsEntry  # type: ignore[import-untyped]
import python_hosts.exception  # type: ignore[import-untyped]
from paramiko.client import SSHClient, AutoAddPolicy
from paramiko import RSAKey, DSSKey
from paramiko.ssh_exception import \
    SSHException, AuthenticationException, PasswordRequiredException
import docker  # type: ignore[import-untyped]

from bottlejwt import JwtPlugin  # type: ignore[import-untyped]
from bottle import Bottle, request, response  # type: ignore[import-untyped, import-not-found]
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import cryptography.exceptions

# config file and list of paths, in the order to try
CONFIG_FILE = 'dnsmasq_updater.conf'
CONFIG_PATHS = [os.path.dirname(os.path.realpath(__file__)), '/etc/', '/conf/']

DEFAULT_LOG_LEVEL = logging.INFO

BLOCK_START = '### docker dnsmasq updater start ###'
BLOCK_END = '### docker dnsmasq updater end ###'


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


def signal_ready(ready_fd, logger):
    """Signal we're ready."""
    if ready_fd:
        logger.info('Initialization done. Signalling readiness.')
        logger.debug('Readiness signal writing to file descriptor %s.', ready_fd)

        try:
            os.write(ready_fd, '\n'.encode())
        except OSError:
            logger.warning('Could not signal file descriptor \'%s\'.', ready_fd)
    else:
        logger.info('Initialization done.')


class ResettableTimer():
    """
    A resettable timer class.

    A timer class so we can delay writes to the external device
    to allow for multiple Docker events in a short space of time
    without hammering the device.
    """

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


class LocalHandler():
    """Handle writing of a local hosts file."""

    def __init__(self, temp_file, **kwargs):
        """Initialize timing."""
        self.params = SimpleNamespace(**kwargs)
        self.temp_file = temp_file
        self.logger = get_logger(self.__class__.__name__, self.params.log_level)
        self.delayed_put = ResettableTimer(self.params.delay, self.put_hostfile)

    def queue_put(self):
        """Delayed writing of the hosts file, allowing for multiple proximate events."""
        self.logger.info('Queued hosts file update.')
        self.delayed_put.reset()

    def put_hostfile(self):
        """Copy the temporary hosts file over the top of the real file."""
        self.logger.info('Writing hosts file: %s', self.params.file)

        try:
            with open(self.temp_file.name, 'r', encoding='utf-8') as temp_file:
                hosts = temp_file.read()
            with open(self.params.file, 'w', encoding='utf-8') as hosts_file:
                hosts_file.write(str(BLOCK_START + '\n' + hosts + BLOCK_END + '\n'))
        except FileNotFoundError as err:
            self.logger.error('Error writing hosts file: %s', err)

        self.exec_restart_command()

    def exec_restart_command(self):
        """Execute command to restart dnsmasq on the local device."""
        restart_cmd = self.params.restart_cmd.strip('\'"')

        try:
            subprocess.run(restart_cmd, check=True)
        except subprocess.CalledProcessError:
            self.logger.error(
                'CalledProcessError: Failed to execute restart command: %s', restart_cmd)


class RemoteHandler():
    """Handle getting/putting/cleaning of local and remote hosts files."""

    def __init__(self, temp_file, **kwargs):
        """Initialize SSH client, temp file and timing."""
        self.params = SimpleNamespace(**kwargs)
        self.logger = get_logger(self.__class__.__name__, self.params.log_level)
        self.temp_file = temp_file
        self.ssh = SSHClient()
        self.ssh.set_missing_host_key_policy(AutoAddPolicy())
        self.delayed_put = ResettableTimer(self.params.delay, self.put_hostfile)
        self.key = False

        self.get_server_ip()

        if self.params.key != '':
            self.logger.debug('self.params.key: %s', self.params.key)
            self.verify_key()

    def get_server_ip(self):
        """
        Check for a valid dnsmasq server IP to use.

        We can't use a hostname for the server because we end up trying to do a
        DNS lookup immediately after instructing dnsmasq to restart.
        """
        try:
            ipaddress.ip_address(self.params.server)
            self.params.server_ip = self.params.server
        except ValueError:
            try:
                self.params.server_ip = socket.getaddrinfo(self.params.server, None)[0][4][0]
            except (ValueError, socket.gaierror):
                self.logger.error('Server (%s) cannot be found.', self.params.server)
                sys.exit(1)

    def verify_key(self):
        """Verify and open key file or error on failure."""
        self.check_key('RSA')
        if not self.key:
            self.check_key('DSA')
            if not self.key:
                self.logger.error('No usable RSA or DSA key found. Halting.')
                sys.exit(1)

    def check_key(self, algorithm):
        """Set self.key if self.params.key is valid for the algorithm."""
        if algorithm == 'RSA':
            algo_class = RSAKey
        elif algorithm == 'DSA':
            algo_class = DSSKey
        else:
            raise ValueError('check_key() works with \'RSA\' or \'DSA\' only.')

        self.logger.debug('Testing if key is %s.', algorithm)
        try:
            key = algo_class.from_private_key_file(self.params.key)
        except PasswordRequiredException:
            if self.params.password != '':
                self.logger.debug('Decrypting %s key.', algorithm)
                try:
                    key = algo_class.from_private_key_file(
                        self.params.key, password=self.params.password)
                except SSHException:
                    self.logger.error('Password for key is not valid.')
                else:
                    self.logger.info('Found valid encrypted %s key.', algorithm)
                    self.key = key
            else:
                self.logger.error('Encrypted %s key, requires password.', algorithm)
        except SSHException:
            self.key = False
        else:
            self.logger.info('Found valid %s key.', algorithm)
            self.key = key

    def open_ssh(self):
        """Check if an SSH connection is open, open a new connection if not."""
        try:
            transport = self.ssh.get_transport()
            transport.send_ignore()
        except (EOFError, AttributeError):
            self.logger.debug('Opening SSH connection.')

            pass_params = {}
            pass_params['username'] = self.params.login

            if self.key:
                pass_params['key_filename'] = self.params.key
            else:
                pass_params['password'] = self.params.password

            try:
                self.ssh.connect(self.params.server_ip, **pass_params)
            except AuthenticationException:
                self.logger.error('Could not authenticate with remote device.')
                sys.exit(1)

    def close_ssh(self):
        """Close the SSH connection."""
        if self.ssh:
            self.logger.debug('Closing SSH connection.')
            self.ssh.close()

    def queue_put(self):
        """
        Delayed putting of the local hosts file on the remote device.

        The delay allows for any additional changes in the immediate future,
        such as expected when a container is restarting, for example.
        """
        self.logger.info('Queued remote hosts file update.')
        self.delayed_put.reset()

    def put_hostfile(self):
        """Put the local hosts file on the remote device."""
        self.open_ssh()
        self.logger.info('Writing remote hosts file: %s', self.params.file)

        with open(self.temp_file.name, 'r', encoding="utf-8") as temp_file:
            hosts_block = BLOCK_START + '\n' + temp_file.read() + BLOCK_END
            exec_return = self.ssh.exec_command(
                'echo -e "' + hosts_block + '" >' + self.params.file)[1]
            if exec_return.channel.recv_exit_status():
                self.logger.error('Could not write remote file.')

        self.exec_restart_command()
        self.close_ssh()

    def exec_restart_command(self):
        """Execute command to update dnsmasq on remote device."""
        self.open_ssh()
        restart_cmd = self.params.restart_cmd.strip('\'"')

        try:
            exec_return = self.ssh.exec_command(restart_cmd)[1]
        except SSHException:
            self.logger.error('SSHException: Failed to execute remote command: %s', restart_cmd)

        if exec_return.channel.recv_exit_status() > 0:
            self.logger.error('Could not execute remote command: %s', restart_cmd)
        else:
            self.logger.info('Executed remote command: %s', restart_cmd)


class HostsHandler():
    """Handle the Hosts object and the individual HostEntry objects."""

    def __init__(self, output_handler, **kwargs):
        """Initialize file handler and timing."""
        self.params = SimpleNamespace(**kwargs)
        self.logger = get_logger(self.__class__.__name__, self.params.log_level)
        self.output_handler = output_handler
        self.temp_file = output_handler.temp_file
        self.delayed_write = ResettableTimer(self.params.local_write_delay, self.write_hosts)
        self.hosts = Hosts(path='/dev/null')

    def parse_hostnames(self, hostnames, id_string):
        """
        Return dictionary items containing IPs and a list of hostnames.

        dict_items([('<IP_1>', ['<hostname1>', '<hostname2>', etc..]),
                    ('<IP_2>', ['<hostname3>', '<hostname4>', etc..]), etc..])
        """
        hostname_dict = defaultdict(set)

        for hostname in hostnames:
            host_ip = self.params.ip
            host_list = set()

            # extra-hosts will include the IP, separated by a colon
            if ':' in hostname:
                hostname, host_ip = hostname.split(':', 1)

            # strip the top level demain, if included
            try:
                hostname = hostname[0:hostname.index('.' + self.params.domain)]
            except ValueError:
                pass

            if not self.hosts.exists(comment=id_string):
                host_list.update([hostname, hostname + '.' + self.params.domain])

                if self.params.prepend_www and not re.search('^www', hostname):
                    host_list.update(['www.' + hostname + '.' + self.params.domain])
                hostname_dict[host_ip].update(host_list)
            else:
                self.logger.debug('comment exists in Hosts: %s', id_string)

        return dict([host_ip, sorted(hostnames)] for host_ip, hostnames in hostname_dict.items())

    def add_hosts(self, short_id, hostnames, agent_id=None, do_write=True):
        """
        Create host's HostsEntry, add it to Hosts object. Optionally write out.

        Setting the comment to a unique string (like a contaienr's 'short_id')
        makes it easy to delete the correct hosts (and only the correct hosts)
        across multiple IPs. Including an identifier for the particular Agent
        that added the host allows esay deletion for all that Agent's hosts if
        the Agent goes down.
        """
        id_string = short_id
        if agent_id is not None:
            id_string += '.' + agent_id

        parsed_hostnames = self.parse_hostnames(hostnames, id_string)
        parsed_items = parsed_hostnames.items()

        if not parsed_items:
            self.logger.debug('Added host(s): no hostnames to add: %s', short_id)
        else:
            try:
                for host_ip, names in parsed_items:
                    self.logger.debug('Adding: %s: %s', host_ip, ', '.join(names))
                    try:
                        hostentry = HostsEntry(entry_type='ipv4', address=host_ip,
                                               names=names, comment=id_string)
                    except python_hosts.exception.InvalidIPv4Address:
                        self.logger.error('Skipping invalid IP address: %s', host_ip)
                    else:
                        if self.params.mode == 'manager':
                            self.hosts.add([hostentry],
                                           allow_address_duplication=True,
                                           allow_name_duplication=True)
                        else:
                            self.hosts.add([hostentry], force=True,
                                           allow_address_duplication=True)

                if do_write:
                    self.queue_write()
                self.logger.info('Added host(s): %s',
                                 ', '.join(sum(parsed_hostnames.values(), [])))

            except ValueError as err:
                self.logger.info('Host already exists, nothing to add.')
                self.logger.debug(err)

        return parsed_items

    def del_hosts(self, id_string):
        """Delete hosts with a comment matching id_string."""
        hostnames = sum([entry.names for entry in self.hosts.entries
                         if id_string in entry.comment], [])

        if not hostnames:
            self.logger.debug(
                'Deleting host(s): no hostnames to delete: %s', id_string)
        else:
            self.logger.info('Deleting host(s): %s', ', '.join(hostnames))
            self.hosts.entries = list(
                set(self.hosts.entries) - {entry for entry in self.hosts.entries
                                           if id_string in entry.comment}
            )

            self.queue_write()

    def queue_write(self):
        """
        Delayed writing of the local and remote hosts files.

        The delay allows for any additional changes in the immediate future,
        such as expected when a container is restarting, for example.
        """
        self.delayed_write.reset()

    def write_hosts(self):
        """Write local hosts file, send it to the output handler."""
        if self.params.log_level == logging.DEBUG:
            self.logger.debug('Writing local hosts temp file: %s', self.temp_file.name)
            for entry in self.hosts.entries:
                print('    ', entry)

        self.hosts.write(path=self.temp_file.name)
        self.temp_file.seek(0)
        self.output_handler.queue_put()


class APIServerHandler(Bottle):
    """Run the API server."""

    def __init__(self, hosts_handler, **kwargs):
        """Initislize the API and configure routes."""
        super().__init__()
        self.params = SimpleNamespace(**kwargs)
        self.logger = get_logger(self.__class__.__name__, self.params.log_level)
        self.hosts_handler = hosts_handler

        if self.params.ready_fd == '':
            self.ready_fd = False
        else:
            self.ready_fd = int(self.params.ready_fd)

        self.install(JwtPlugin(self.validation, self.params.api_key, algorithm="HS512"))
        self.permissions = {"user": 0, "service": 1, "admin": 2}

        self.route('/auth', callback=self.auth, method='POST')
        self.route('/status', callback=self.status)
        self.route('/add', callback=self.add_hosts, method='POST', auth='user')
        self.route('/del/<short_id>', callback=self.del_hosts, method='DELETE', auth='user')

        self.instance_id = hash(time.time())

        signal_ready(self.ready_fd, self.logger)

    def validation(self, auth, user):
        """Validate request."""
        return self.permissions[auth["type"]] >= self.permissions[user]

    def auth(self):
        """
        Authenticate a node.

        request: {'clientId': <client_id>, 'clientSecret': <password>}
        response: {'access_token': <token>, 'type': 'bearer'}
        """
        client_id = request.headers.get('clientId')
        client_secret = request.headers.get('clientSecret')

        try:
            kdf = Scrypt(salt=str.encode(client_id), length=32, n=2**14, r=8, p=1)
        except TypeError as err:
            self.logger.error('Invalid auth request: %s', err)
            response.status = 401
            return "Unauthorized."

        try:
            kdf.verify(str.encode(self.params.api_key), bytes.fromhex(client_secret))
        except cryptography.exceptions.InvalidKey as err:
            self.logger.warning('Invalid key from client %s: %s', client_id, err)
            response.status = 401
            return "Unauthorized."

        user = {"client_id": client_id, "client_secret": client_secret, "type": "user"}

        if not user:
            raise self.HTTPError(403, "Invalid user or password")
        user["exp"] = time.time() + 86400
        return {"access_token": JwtPlugin.encode(user), "type": "bearer"}

    def status(self):
        """
        Return the instance ID.

        This is a general up/ready indicator, as well as providing a unique ID
        so the clients can tell if the API has restarted (and re-initialize the
        hosts data accordingly).
        """
        # self.logger.debug('Status check: %s', request.remote_addr)
        response.add_header('DMU-API-ID', self.instance_id)
        return str(self.instance_id)

    def add_hosts(self):
        """Add new hosts."""
        self.logger.debug('add_hosts: %s', request.json)
        self.hosts_handler.add_hosts(request.json['short_id'],
                                     request.json['hostnames'],
                                     request.json.get('from', None))
        response.add_header('DMU-API-ID', self.instance_id)
        return str(self.instance_id)

    def del_hosts(self, short_id):
        """Delete hosts."""
        self.logger.debug('del_hosts: %s', short_id)
        self.hosts_handler.del_hosts(short_id)

        response.status = 204
        response.add_header('DMU-API-ID', self.instance_id)
        return str(self.instance_id)

    def start_monitor(self):
        """
        Run the API.

        Clear sys.argv before calling run(), else args get sent to the backend.
        """
        self.logger.info('Starting API..')

        sys.argv = sys.argv[:1]
        if self.params.api_backend is None:
            self.run(host=self.params.api_address, port=self.params.api_port,
                     debug=self.params.debug)
        else:
            self.run(host=self.params.api_address, server=self.params.api_backend,
                     port=self.params.api_port, debug=self.params.debug)


class DockerHandler():
    """Handle connecting to the Docker socket and the data it produces."""

    client = None

    def __init__(self, hosts_handler, **kwargs):
        """Initialize variables, do nothing until start_monitor()."""
        self.params = SimpleNamespace(**kwargs)
        self.logger = get_logger(self.__class__.__name__, self.params.log_level)
        self.hosts_handler = hosts_handler
        self.scan_success = False

        self.event_verbs = {'start': 'starting',
                            'stop': 'stopping',
                            'connect': 'connecting to',
                            'disconnect': 'disconnecting from'}

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

        swarm_status = self.client.info()['Swarm']['LocalNodeState']
        match swarm_status:
            case 'inactive':
                self.logger.info('Docker standalone detected.')
            case 'active':
                self.logger.info('Docker Swarm mode detected.')
                if self.params.mode != 'manager':
                    # pylint: disable=line-too-long
                    self.logger.error('Can only run in a Swarm as a manager, run with `--manager` argument')
                    self.logger.error('Use `dnsmasq_updater_agent.py` for monitoring Swarm devices.')
                    # pylint: enable=line-too-long
                    self.logger.error('Exiting.')
                    sys.exit(2)
            case _:
                self.logger.error('Swarm detection failed: %s', swarm_status)
                sys.exit(1)

    def get_hostnames(self, container):
        """
        Return a list of hostnames for a container or service.

        Include any IP address override in the form '<hostname>:<address>'
        """
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
            return container.labels['dnsmasq.updater.ip']
        except KeyError:
            return None

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
            hostnames = self.get_hostnames(container)
            if hostnames is None:
                continue
            self.logger.info('Found %s: %s', container.name, ', '.join(hostnames))
            if self.hosts_handler.add_hosts(container.short_id, hostnames, do_write=False):
                self.scan_success = True

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

        for container in network.attrs['Containers']:
            try:
                container_object = self.client.containers.get(container)
            except docker.errors.NotFound:
                continue

            hostnames = self.get_hostnames(container_object)
            self.logger.info('Found %s: %s', container_object.name, ', '.join(hostnames))
            if self.hosts_handler.add_hosts(container_object.short_id, hostnames):
                self.scan_success = True

        self.logger.info('Finished scanning containers on \'%s\' network.', self.params.network)

    def handle_container_event(self, event):
        """Handle a container event."""
        if 'dnsmasq.updater.enable' not in event['Actor']['Attributes']:
            return

        container = self.client.containers.get(event['Actor']['ID'])
        short_id = container.short_id
        name = container.name

        self.logger.info('Detected %s %s.', name, self.event_verbs[event['status']])

        if event['status'] == 'stop':
            self.hosts_handler.del_hosts(short_id)
        elif event['status'] == 'start':
            hostnames = self.get_hostnames(container)
            if hostnames is not None:
                self.hosts_handler.add_hosts(short_id, hostnames)

    def handle_network_event(self, event):
        """Handle a network event."""
        try:
            container = self.client.containers.get(event['Actor']['Attributes']['container'])
        except docker.errors.NotFound:
            self.logger.warning(
                'Container %s not found.', event['Actor']['Attributes']['container'])
            container = None

        if container is not None:
            short_id = container.short_id

            self.logger.info('Detected %s %s \'%s\' network.', container.name,
                             self.event_verbs[event['Action']],
                             event['Actor']['Attributes']['name'])

            if event['Action'] == 'disconnect':
                self.hosts_handler.del_hosts(short_id)
            elif event['Action'] == 'connect':
                self.hosts_handler.add_hosts(short_id, self.get_hostnames(container))

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
        self.get_client()
        self.scan_runnning_containers()

        if self.params.network:
            self.scan_network_containers()
        if self.scan_success:
            self.hosts_handler.queue_write()

        events = self.client.events(decode=True)
        signal_ready(self.ready_fd, self.logger)

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
            'domain': 'docker',
            'prepend_www': False,
            'docker_socket': 'unix://var/run/docker.sock',
            'network': '',
            'server': '',
            'port': '22',
            'login': '',
            'password': '',
            'key': '',
            'file': '',
            'restart_cmd': '',
            'mode': 'standalone',
            'location': 'remote',
            'api_address': '0.0.0.0',
            'api_port': '8080',
            'api_key': '',
            'api_backend': None,
            'log_level': self.log_level,
            'delay': 10,
            'local_write_delay': 3,
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
                self.defaults.update(dict(config.items("dns")))
                self.defaults.update(dict(config.items("hosts")))
                self.defaults.update(dict(config.items("docker")))
                self.defaults['prepend_www'] = config['dns'].getboolean('prepend_www')
                self.defaults.update(dict(config.items("api")))

                self.logger.debug('Args from config file: %s', json.dumps(self.defaults, indent=4))
            else:
                self.logger.error('Config file (%s) does not exist.',
                                  self.args.config_file)

    def parse_command_line(self):
        """
        Parse command line arguments.

        Overwrite the default config and anything found in a config file.
        """
        parser = argparse.ArgumentParser(
            description='Docker Dnsmasq Updater', parents=[self.config_parser])
        parser.set_defaults(**self.defaults)

        parser.add_argument(
            '--local_write_delay', action='store', type=int, help=argparse.SUPPRESS)
        parser.add_argument(
            '--ready_fd', action='store', metavar='INT',
            help='set to an integer to enable signalling readiness by writing '
            'a new line to that integer file descriptor')

        mode_group = parser.add_argument_group(title='Mode')
        mode = mode_group.add_mutually_exclusive_group()
        mode.add_argument(
            '--standalone', action='store_const', dest='mode', const='standalone',
            help='running on a standalone Docker host (default)')
        mode.add_argument(
            '--manager', action='store_const', dest='mode', const='manager',
            help='bring up the API and run as the manager for multiple Docker nodes')

        docker_group = parser.add_argument_group(title='Docker')
        docker_group.add_argument(
            '-D', '--docker_socket', action='store', metavar='SOCKET',
            help='path to the docker socket (default: \'%(default)s\')')
        docker_group.add_argument(
            '-n', '--network', action='store', metavar='NETWORK',
            help='Docker network to monitor')

        dns_group = parser.add_argument_group(title='DNS')
        dns_group.add_argument(
            '-i', '--ip', action='store', metavar='IP',
            help='default IP for the DNS records')
        dns_group.add_argument(
            '-d', '--domain', action='store', metavar='DOMAIN',
            help='domain/zone for the DNS record (default: \'%(default)s\')')
        dns_group.add_argument(
            '-w', '--prepend_www', action='store_true',
            help='add \'www\' subdomains for all hostnames')

        hosts_group = parser.add_argument_group(title='hosts file')
        location_group = hosts_group.add_mutually_exclusive_group()
        location_group.add_argument(
            '--remote', action='store_const', dest='location', const='remote',
            help='write to a remote hosts file, via SSH (default)')
        location_group.add_argument(
            '--local', action='store_const', dest='location', const='local',
            help='write to a local hosts file')
        hosts_group.add_argument(
            '-f', '--file', action='store', metavar='FILE',
            help='the hosts file (including path) to write')
        hosts_group.add_argument(
            '-r', '--restart_cmd', action='store', metavar='COMMAND',
            help='the dnsmasq restart command to execute')
        hosts_group.add_argument(
            '-t', '--delay', action='store', metavar='SECONDS', type=int,
            help='delay for writes to the hosts file (default: \'%(default)s\')')

        remote_hosts_group = parser.add_argument_group(
            title='Remote hosts file (needed by --remote)')
        remote_hosts_group.add_argument(
            '-s', '--server', action='store', metavar='SERVER',
            help='dnsmasq server address')
        remote_hosts_group.add_argument(
            '-P', '--port', action='store', metavar='PORT',
            help='port for SSH on the dnsmasq server (default: \'%(default)s\')')
        remote_hosts_group.add_argument(
            '-l', '--login', action='store', metavar='USERNAME',
            help='login name for the dnsmasq server')
        remote_hosts_group.add_argument(
            '-k', '--key', action='store', metavar='FILE',
            help='identity/key file for SSH to the dnsmasq server')
        remote_hosts_group.add_argument(
            '-p', '--password', action='store', metavar='PASSWORD',
            help='password for the dnsmasq server OR for an encrypted SSH key')

        api_group = parser.add_argument_group(
            title='API server (needed by --manager)')
        api_group.add_argument(
            '--api_address', action='store', metavar='IP',
            help='address for API to listen on (default: \'%(default)s\')')
        api_group.add_argument(
            '--api_port', action='store', metavar='PORT',
            help='port for API to listen on (default: \'%(default)s\')')
        api_group.add_argument(
            '--api_key', action='store', metavar='KEY', help='API access key')
        api_group.add_argument(
            '--api_backend', action='store', metavar='STRING',
            help='API backend (refer to Bottle module docs for details)')

        self.args = parser.parse_args()
        self.logger.debug('Parsed command line:\n%s',
                          json.dumps(vars(self.args), indent=4))

    def check_args(self):
        # pylint: disable=too-many-branches
        """Check we have all the information we need to run."""
        if self.args.ip == '':
            self.logger.error('No host IP specified.')
            sys.exit(1)

        try:
            ipaddress.ip_address(self.args.ip)
        except ValueError:
            self.logger.error('Specified host IP (%s) is invalid.', self.args.ip)
            sys.exit(1)

        if self.args.file == '':
            self.logger.error('No hosts file specified.')
            sys.exit(1)

        if self.args.restart_cmd == '':
            self.logger.error('No dnsmasq restart command specified.')
            sys.exit(1)

        if not isinstance(self.args.delay, int):
            self.logger.error('Specified delay (%s) is invalid.', self.args.delay)
            sys.exit(1)

        if self.args.location == 'remote':
            if self.args.login == '':
                self.logger.error('No remote login name specified.')
                sys.exit(1)

            if self.args.key == '':
                if self.args.password == '':
                    self.logger.error('No remote password or key specified.')
                    sys.exit(1)
            elif not os.path.exists(self.args.key):
                self.logger.error('Key file (%s) does not exist.', self.args.key)
                sys.exit(1)

            if self.args.server == '':
                self.logger.error('No remote server specified.')
                sys.exit(1)

        if self.args.mode == 'manager' and self.args.api_key == '':
            self.logger.error('No manager API key specified.')
            sys.exit(1)

    def get_args(self):
        """Return all config parameters."""
        return self.args


def main():
    """Do all the things."""
    config = ConfigHandler()
    args = vars(config.get_args())

    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        if args['location'] == 'local':
            output_handler = LocalHandler(temp_file, **args)
        else:
            output_handler = RemoteHandler(temp_file, **args)

        hosts_handler = HostsHandler(output_handler, **args)

        if args['mode'] == 'manager':
            input_handler = APIServerHandler(hosts_handler, **args)
        else:
            input_handler = DockerHandler(hosts_handler, **args)

        try:
            input_handler.start_monitor()
        except SystemExit:
            pass
        finally:
            hosts_handler.delayed_write.cancel()
            output_handler.delayed_put.cancel()
            print('Exiting.')


if __name__ == '__main__':
    main()
