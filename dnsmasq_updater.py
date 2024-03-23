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
import socket
import ipaddress
import tempfile
import time
import re

from threading import Timer
from types import SimpleNamespace
from collections import defaultdict
from typing import Dict

from python_hosts import Hosts, HostsEntry  # type: ignore
from paramiko.client import SSHClient, AutoAddPolicy, RSAKey, DSSKey  # type: ignore
from paramiko.ssh_exception import \
    SSHException, AuthenticationException, PasswordRequiredException
import docker  # type: ignore


# list possible configuration file locations in the order they should
# be tried, use first match
CONFIG_FILE = 'dnsmasq_updater.conf'
CONFIG_PATHS = [os.path.dirname(os.path.realpath(__file__)), '/etc/', '/conf/']

DEFAULT_LOG_LEVEL = logging.INFO

# these are mostly just to indicate hosts managed by this script in the case
# where hosts are merged into an existing hosts file on the dnsmasq server
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


class ResettableTimer():
    """
    A resettable timer class.

    A timer class so we can delay writes to the external device
    to allow for multiple Docker events in a short space of time
    without hammering the device.
    """

    def __init__(self, delay, function):
        """Initialize timing."""
        self.running = False
        self.delay = delay
        self.function = function
        self.timer = Timer(self.delay, self.function)

    def __set(self):
        self.timer = Timer(self.delay, self.function)

    def start(self):
        """If not running, start timer."""
        if not self.running:
            self.__set()
            self.timer.start()
            self.running = True

    def cancel(self):
        """If running, cancel timer."""
        if self.running:
            self.timer.cancel()
            self.running = False

    def reset(self):
        """Reset timer."""
        self.cancel()
        self.start()


class RemoteHandler():
    """Handle getting/putting/cleaning of local and remote hosts files."""

    def __init__(self, temp_file, **kwargs):
        """Initialize SSH client, temp file and timings then get remote hosts."""
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

        self.get_hostfile()

    def get_server_ip(self):
        """
        Check for a valid dnsmasq server IP to use.

        We can't use a hostname for the server because we end up trying to do a
        DNS lookup immediately after instructing dnsmasq to restart, and it's
        generally unwise to attempt a DNS resolution when we've just shut down
        the DNS server.
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
            raise Exception('check_key() works with \'RSA\' or \'DSA\' only.')

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

    def get_hostfile(self):
        """Get the specified hosts file from the remote device."""
        self.logger.info('Reading remote hosts file: %s', self.params.file)

        self.open_ssh()
        exec_return = self.ssh.exec_command('cat ' + self.params.file)[1]

        remote_hosts = []
        if exec_return.channel.recv_exit_status():
            self.logger.info('Remote hosts file does not exist, it will be created.')
        else:
            remote_hosts = exec_return.readlines()

        self.hosts = remote_hosts

    def queue_put(self):
        """
        Delayed putting of the local hosts file on the remote device.

        The delay allows for any additional changes in the immediate future,
        such as expected when a container is restarting, for example.
        """
        self.logger.info('Queued remote host file update.')
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

        self.exec_remote_command()
        self.close_ssh()

    def exec_remote_command(self):
        """Execute command to update dnsmasq on remote device."""
        self.open_ssh()
        remote_cmd = self.params.remote_cmd.strip('\'"')

        try:
            exec_return = self.ssh.exec_command(remote_cmd)[1]
        except SSHException:
            self.logger.error('SSHException: Failed to execute remote command: %s', remote_cmd)

        if exec_return.channel.recv_exit_status() > 0:
            self.logger.error('Could not execute remote command: %s', remote_cmd)
        else:
            self.logger.info('Executed remote command: %s', remote_cmd)


class HostsHandler():
    """Handle the Hosts object and the individual HostEntry objects."""

    def __init__(self, remote_handler, **kwargs):
        """Initialize file handler and timing then populate from remote."""
        self.params = SimpleNamespace(**kwargs)
        self.logger = get_logger(self.__class__.__name__, self.params.log_level)
        self.remote_handler = remote_handler
        self.temp_file = remote_handler.temp_file
        self.delayed_write = ResettableTimer(self.params.local_write_delay, self.write_hosts)

        self.hosts = Hosts(path='/dev/null')

        # There's not really a good reason to import the existing hosts file
        # during init since we don't import it again before writing, which loses
        # any changes made by dnsmasq in the mean time.
        #
        # We're better off using an additional/external hosts file just for this
        # script and feeding it to dnsmasq with the '-H' argument.
        #
        # This also avoids having to parse hosts and figure out which are managed
        # here and which aren't.

        # self.get_remote_hosts()

    # def get_remote_hosts(self):
    #     """
    #     Parse remote hosts file into python-hosts.
    #
    #     This is not being used and can probably be removed, as per the comment
    #     above. To keep it, we'd need to properly distinguish between hosts we
    #     manage and hosts we don't. The BLOCK_START/END comment strings won't
    #     necesarily keep their position in the Hosts class, so aren't useful as
    #     delimiters if added as a HostEntry. We'd need to pull the remote hosts
    #     file before each write and do some grep/sed/regex magic to parse and
    #     insert delimiters then.
    #     """
    #     self.logger.debug('Cleaning remote hosts..')
    #
    #     for line in self.remote_handler.hosts:
    #         if any(x in line for x in [BLOCK_START, BLOCK_END]):
    #             continue
    #
    #         self.logger.debug('line: %s', line)
    #
    #         line_type = HostsEntry.get_entry_type(line)
    #
    #         self.logger.debug('line_type: %s', line_type)
    #
    #         if line_type in ['ipv4', 'ipv6']:
    #             try:
    #                 self.hosts.add([HostsEntry.str_to_hostentry(line)])
    #             except AttributeError:
    #                 self.logger.warning('Skipping unparseable line in hosts file: %s', line)
    #         elif line_type == 'comment':
    #             self.hosts.add([HostsEntry(entry_type='comment', comment=line)])
    #         elif line_type == 'blank':
    #             # python_hosts.Hosts.add doesn't seem to work for blank lines.
    #             # We'll have to use the internal class methods directly.
    #             self.logger.debug('blank line: %s', line)
    #             self.hosts.entries.append(HostsEntry(entry_type="blank"))
    #         else:
    #             self.logger.warning('Skipping unknown line type in hosts file: %s', line)
    #
    #     if self.params.log_level == logging.DEBUG:
    #         self.logger.debug('Cleaned remote hosts: ')
    #         for entry in self.hosts.entries:
    #             print('    ', entry)

    def parse_hostnames(self, hostnames):
        """
        Return dictionary items containing IPs and a list of hostnames.

        dict_items([
            ('<IP_1>', ['<hostname1>', '<hostname2>', etc..]),
            ('<IP_2>', ['<hostname3>', '<hostname4>', etc..]),
            etc..])
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

            if not self.hosts.exists(names=[hostname]):
                host_list.update([hostname, hostname + '.' + self.params.domain])

                if self.params.prepend_www and not re.search('^www', hostname):
                    host_list.update(['www.' + hostname + '.' + self.params.domain])

                hostname_dict[host_ip].update(host_list)

        return dict([host_ip, sorted(hostnames)] for host_ip, hostnames in hostname_dict.items())

    def add_hosts(self, container_id, hostnames, do_write=True):
        """
        Create host's HostsEntry, add it to Hosts object. Optionally write out.

        Setting the comment to a unique string (like a contaienr's 'short_id')
        makes it easy to delete the correct hosts (and only the correct hosts)
        across multiple IPs.
        """
        parsed_hostnames = self.parse_hostnames(hostnames)
        parsed_items = parsed_hostnames.items()

        try:
            for host_ip, names in parsed_items:
                self.logger.debug('Adding: %s: %s', host_ip, ', '.join(names))
                hostentry = HostsEntry(entry_type='ipv4', address=host_ip,
                                       names=names, comment=container_id)
                self.hosts.add([hostentry], force=True, allow_address_duplication=True)

            if do_write:
                self.queue_write()

            self.logger.info('Added host(s): %s',
                             ', '.join(sum(parsed_hostnames.values(), [])))

        except ValueError:
            self.logger.info('Host already exists, nothing to add.')

        return parsed_items

    def del_hosts(self, comment):
        """Delete hosts with matching comment."""
        self.logger.info('Deleting hostnames: %s',
                         ', '.join(sum([entry.names for entry in self.hosts.entries
                                        if entry.comment == comment], [])))

        self.hosts.entries = list(
            set(self.hosts.entries) - {entry for entry in self.hosts.entries
                                       if entry.comment == comment}
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
        """Write local hosts file, put it on the remote device."""
        if self.params.log_level == logging.DEBUG:
            self.logger.debug('Writing local hosts temp file: %s', self.temp_file.name)
            for entry in self.hosts.entries:
                print('    ', entry)

        self.hosts.write(path=self.temp_file.name)
        self.temp_file.seek(0)
        self.remote_handler.queue_put()


class DockerHandler():
    """Handle connecting to the Docker socket and the data it produces."""

    client = None

    def __init__(self, hosts_handler, **kwargs):
        """Initialize variables, do nothing until run()."""
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
                if self.hosts_handler.add_hosts(service.short_id, names, do_write=False):
                    self.scan_success = True

        else:
            containers = self.client.containers.list(
                filters={"label": "dnsmasq.updater.enable", "status": "running"})
            for container in containers:
                names = self.get_hostnames(container)
                self.logger.info('Found %s: %s', container.name, ', '.join(names))
                if self.hosts_handler.add_hosts(container.short_id, names, do_write=False):
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
            if self.hosts_handler.add_hosts(container.short_id, names, do_write=False):
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

    def run(self):
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
            'remote_cmd': '',
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
                self.defaults.update(dict(config.items("dns")))
                self.defaults.update(dict(config.items("local")))
                self.defaults.update(dict(config.items("remote")))
                self.defaults.update(dict(config.items("docker")))
                self.defaults['prepend_www'] = config['dns'].getboolean('prepend_www')

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
            description='Docker Dnsmasq Updater', parents=[self.config_parser])
        parser.set_defaults(**self.defaults)
        parser.add_argument(
            '-i', '--ip', action='store', metavar='IP',
            help='IP for the DNS record')
        parser.add_argument(
            '-d', '--domain', action='store', metavar='DOMAIN',
            help='domain/zone for the DNS record (default: \'%(default)s\')')
        parser.add_argument(
            '-w', '--prepend_www', action='store_true',
            help='add \'www\' subdomains for all hostnames')
        parser.add_argument(
            '-D', '--docker_socket', action='store', metavar='SOCKET',
            help='path to the docker socket (default: \'%(default)s\')')
        parser.add_argument(
            '-n', '--network', action='store', metavar='NETWORK',
            help='Docker network to monitor')
        parser.add_argument(
            '-s', '--server', action='store', metavar='SERVER',
            help='dnsmasq server address')
        parser.add_argument(
            '-P', '--port', action='store', metavar='PORT',
            help='port for SSH on the dnsmasq server (default: \'%(default)s\')')
        parser.add_argument(
            '-l', '--login', action='store', metavar='USERNAME',
            help='login name for the dnsmasq server')
        parser.add_argument(
            '-k', '--key', action='store', metavar='FILE',
            help='identity/key file for SSH to the dnsmasq server')
        parser.add_argument(
            '-p', '--password', action='store', metavar='PASSWORD',
            help='password for the dnsmasq server OR for an encrypted SSH key')
        parser.add_argument(
            '-f', '--file', action='store', metavar='FILE',
            help='the file (including path) to write on the dnsmasq server')
        parser.add_argument(
            '-r', '--remote_cmd', action='store', metavar='COMMAND',
            help='the update command to execute on the dnsmasq server')
        parser.add_argument(
            '-t', '--delay', action='store', metavar='SECONDS', type=int,
            help='delay for writes to the dnsmasq server (default: \'%(default)s\')')
        parser.add_argument(
            '--local_write_delay', action='store', type=int,
            help=argparse.SUPPRESS)
        parser.add_argument(
            '--ready_fd', action='store', metavar='INT',
            help='set to an integer to enable signalling readiness by writing '
            'a new line to that integer file descriptor')
        self.args = parser.parse_args()

        self.logger.debug('Parsed command line:\n%s',
                          json.dumps(vars(self.args), indent=4))

    def check_args(self):
        """Check we have all the information we need to run."""
        if self.args.login == '':
            self.logger.error('No login name specified.')
            sys.exit(1)

        if self.args.key == '':
            if self.args.password == '':
                self.logger.error('No password or key specified.')
                sys.exit(1)
        else:
            if not os.path.exists(self.args.key):
                self.logger.error('Key file (%s) does not exist.', self.args.key)
                sys.exit(1)

        if self.args.ip == '':
            self.logger.error('No host IP specified.')
            sys.exit(1)
        else:
            try:
                ipaddress.ip_address(self.args.ip)
            except ValueError:
                self.logger.error('Specified host IP (%s) is invalid.', self.args.ip)
                sys.exit(1)

        if self.args.server == '':
            self.logger.error('No remote server specified.')
            sys.exit(1)

        if self.args.file == '':
            self.logger.error('No remote file specified.')
            sys.exit(1)

        if self.args.remote_cmd == '':
            self.logger.error('No remote command specified.')
#            self.logger.error(self.args.remote_cmd)
            sys.exit(1)

        if not isinstance(self.args.delay, int):
            self.logger.error('Specified delay (%s) is invalid.', self.args.delay)
            sys.exit(1)

    def get_args(self):
        """Return all config parameters."""
        return self.args


def main():
    """Do all the things."""
    config = ConfigHandler()
    args = config.get_args()

    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        remote_handler = RemoteHandler(temp_file, **vars(args))
        hosts_handler = HostsHandler(remote_handler, **vars(args))
        docker_handler = DockerHandler(hosts_handler, **vars(args))

        try:
            docker_handler.run()
        except SystemExit:
            pass
        finally:
            hosts_handler.delayed_write.cancel()
            remote_handler.delayed_put.cancel()


if __name__ == '__main__':
    main()
