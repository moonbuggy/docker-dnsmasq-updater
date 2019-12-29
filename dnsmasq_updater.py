#!/usr/bin/env python3

'''
Docker Dnsmasq Updater

Use the Docker socket to update a remote dnsmasq server with container hostnames
'''

from os import path, makedirs, write
import sys
import signal
import logging
import argparse
import configparser
import errno
import json
import socket
import ipaddress
from types import SimpleNamespace

import docker
from python_hosts import Hosts, HostsEntry
from paramiko import SSHClient, AutoAddPolicy, RSAKey, DSSKey
from paramiko.ssh_exception import SSHException, AuthenticationException, PasswordRequiredException

## list possible configuration file locations in the order they should
## be tried, use first match
CONFIG_FILE = 'dnsmasq_updater.conf'
CONFIG_PATHS = [path.dirname(path.realpath(__file__)), '/etc/', '/conf/']

DEFAULT_LOG_LEVEL = logging.INFO

STDOUT_HANDLER = logging.StreamHandler(sys.stdout)
STDOUT_HANDLER.setFormatter(
	logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

def signal_handler(_sig, _frame):
	''' Handle SIGINT cleanly. '''

	print('\nSignal interrupt. Exiting.')
	sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

loggers = {}

def get_logger(class_name, log_level):
	''' get logger objects for individual classes '''

	name = path.splitext(__file__)[0]
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

class FileHandler():
	''' Handle getting/putting/cleaning of local and remote hosts files '''

	args = {}
	block_start = '### dnsmasq updater start ###'

	def __init__(self, **kwargs):
		self.params = SimpleNamespace(**kwargs)

		self.logger = get_logger(self.__class__.__name__, self.params.log_level)

		self.logger.debug('parameters:\n%s', json.dumps(vars(self.params), indent=4))

		self.make_temp_file()

		self.ssh = SSHClient()
		self.ssh.set_missing_host_key_policy(AutoAddPolicy())

		self.get_server_ip()

		if self.params.key != '':
			self.logger.debug('self.params.key: %s', self.params.key)
			self.verify_key()

		self.get_clean_hosts()

	def make_temp_file(self):
		''' make the local temp file '''

		backup_temp_file = '/tmp/dnsmasq-updater.temp'

		if not path.exists(path.dirname(self.params.temp_file)):
			try:
				makedirs(path.dirname(self.params.temp_file))
			except OSError as err:
				if err.errno != errno.EEXIST:
					self.logger.notice(
						'Cannot create folder for specified temporary file (\'%s\'), ' \
						'defaulting to \'%s\'', self.params.temp_file, backup_temp_file)
					self.params.temp_file = backup_temp_file

	def get_server_ip(self):
		'''
		check for a valid dnsmasq server IP to use

		we can't use a hostname for the server because we end up trying to do a DNS
		lookup immediately after instructing dnsmasq to restart, and it's generally
		unwise to attempt a DNS resolution when we've just shut down the DNS server
		'''
		try:
			self.params.server_ip = ipaddress.ip_address(self.params.server)
		except ValueError:
			try:
				self.params.server_ip = socket.getaddrinfo(self.params.server, None)[0][4][0]
			except (ValueError, socket.gaierror):
				self.logger.error('Server (%s) cannot be found.', self.params.server)
				sys.exit(1)

	def verify_key(self):
		''' verify and open key file or error on failure '''

		self.key = self.check_rsa()
		if not self.key:
			self.key = self.check_dsa()
			if not self.key:
				self.logger.error('No usable RSA or DSA key found. Halting.')
				sys.exit(1)

	def check_rsa(self):
		''' return key if key is RSA, otherwise return False '''

		self.logger.debug('Testing if key is RSA.')
		try:
			key = RSAKey.from_private_key_file(self.params.key)
		except PasswordRequiredException:
			if self.params.password != '':
				self.logger.debug('Decrypting RSA key.')
				try:
					key = RSAKey.from_private_key_file(self.params.key, password=self.params.password)
				except SSHException:
					self.logger.error('Password for key is not valid.')
				else:
					self.logger.info('Found valid encrypted RSA key.')
					return key
			else:
				self.logger.error('Encrypted RSA key, requires password.')
		except SSHException:
			return False
		else:
			self.logger.info('Found valid RSA key.')
			return key

		return False

	def check_dsa(self):
		''' return key if key is DSA, otherwise return False '''

		self.logger.debug('Testing if key is DSA.')
		try:
			key = DSSKey.from_private_key_file(self.params.key)
		except PasswordRequiredException:
			if self.params.password != '':
				self.logger.debug('Decrypting DSA key.')
				try:
					key = DSSKey.from_private_key_file(self.params.key, password=self.params.password)
				except SSHException:
					self.logger.error('No valid password for DSA key.')
				else:
					self.logger.info('Found valid encrypted DSA key.')
					return key
			else:
				self.logger.error('Encrypted DSA key, requires password.')
		except SSHException:
			return False
		else:
			self.logger.info('Found valid DSA key.')
			return key

		return False

	def open_ssh(self):
		'''
		check if an SSH connection is already open,
		open a new connection if necessary
		'''

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
		''' close the SSH connection '''
		if self.ssh:
			self.logger.debug('Closing SSH connection.')
			self.ssh.close()

	def get_hostfile(self):
		''' get the specified hosts file from the remote device '''

		self.logger.info('Reading remote hosts file: %s', self.params.file)

		self.open_ssh()
		exec_return = self.ssh.exec_command('cat ' + self.params.file)[1]

		remote_hosts = []
		if exec_return.channel.recv_exit_status():
			self.logger.info('Remote hosts file does not exist, it will be created.')
		else:
			remote_hosts = exec_return.readlines()

		with open(self.params.temp_file, 'w') as file:
			for line in remote_hosts:
				file.write(line)


	def put_hostfile(self):
		''' put the local hosts file on the remote device '''
		self.open_ssh()
		self.logger.info('Writing remote hosts file: %s', self.params.file)

		with open(self.params.temp_file, 'r') as temp_file:
			exec_return = self.ssh.exec_command(
				'echo -e "' + temp_file.read() + '" > ' + self.params.file)[1]
			if exec_return.channel.recv_exit_status():
				self.logger.error('Could not write remote file.')

		self.exec_remote_command()
		self.close_ssh()

	def get_clean_hosts(self):
		''' get hosts file from remote device and remove existing dnsmasq_update entries '''

		self.get_hostfile()

		hosts_clean = []

		with open(self.params.temp_file, 'r+') as file:
			for line in file:
				if self.block_start in line:
					break
				hosts_clean.append(line.rstrip('\r\n'))

		try:
			while hosts_clean[0] == '':
				hosts_clean.pop(0)
		except IndexError:
			pass

		try:
			while hosts_clean[-1] == '':
				hosts_clean.pop(-1)
		except IndexError:
			pass

		hosts_clean.append('')
		self.logger.debug('hosts_clean:\n%s', json.dumps(hosts_clean, indent=4))

		with open(self.params.temp_file, 'w+') as file:
			for line in hosts_clean:
				file.write(line + '\n')

	def exec_remote_command(self):
		''' execute command to update dnsmasq on remote device '''

		self.open_ssh()
		remote_cmd = self.params.remote_cmd.strip('\'"')

		self.logger.debug('remote_cmd: %s', remote_cmd)
		try:
			exec_return = self.ssh.exec_command(remote_cmd)[1]
		except SSHException:
			self.logger.error('SSHException: Failed to execute remote command: %s', remote_cmd)

		if exec_return.channel.recv_exit_status():
			self.logger.error('Could not execute remote command: %s', remote_cmd)
		else:
			self.logger.info('Restarted dnsmasq on remote device.')


class HostsHandler():
	''' Handle the Hosts object and the individual HostEntry objects '''

	def __init__(self, file_handler, **kwargs):
		self.params = SimpleNamespace(**kwargs)

		self.logger = get_logger(self.__class__.__name__, self.params.log_level)
		self.logger.debug('parameters:\n%s', json.dumps(vars(self.params), indent=4))

		self.file_handler = file_handler
		self.block_start = self.file_handler.block_start

		self.hosts = Hosts(path=self.params.temp_file)
		if not self.hosts.exists(comment=self.block_start):
			comment = HostsEntry(entry_type='comment', comment=self.block_start)
			self.hosts.add([comment], force=True, allow_address_duplication=True)

	def parse_hostnames(self, hostnames):
		''' return a list of hostnames with and without the zone attached on each '''

		parsed_hostnames = []

		for hostname in hostnames:
			try:
				hostname = hostname[0:hostname.index('.' + self.params.domain)]
			except ValueError:
				pass

			zoned_name = hostname + '.' + self.params.domain
			if (zoned_name) not in parsed_hostnames:
				parsed_hostnames.append(zoned_name)

			if hostname not in parsed_hostnames:
				parsed_hostnames.append(hostname)

		return parsed_hostnames

	def add_hosts(self, hosts_list, do_write=False):
		''' iterate through a list of hosts, add each host's names individually '''

		for hostnames in hosts_list:
			self.add_host(hostnames)

		if do_write:
			self.write_hosts()

	def add_host(self, hostnames, do_write=False):
		''' create HostsEntry for a host and at it to Hosts object, optionally write out '''

		do_add = False

		names = self.parse_hostnames(hostnames)
		for name in names:
			if not self.hosts.exists(names=[name]):
				do_add = True
				break

		if do_add:
			hostentry = HostsEntry(entry_type='ipv4', address=self.params.ip, names=names)
			self.hosts.add([hostentry], force=True, allow_address_duplication=True)

			self.logger.info('Added host: %s', names)

			if do_write:
				self.write_hosts()
		else:
			self.logger.debug('Host already exists, skipping: %s', names)

	def del_host(self, hostnames, do_write=False):
		''' delete a host's names, optionally write out '''

		valid_hostname = False

		self.logger.debug('del_host: %s', hostnames)
		for host in hostnames:
			if self.hosts.exists(names=[host]):
				self.hosts.remove_all_matching(name=host)
				self.logger.info('Deleted hosts: %s', hostnames)
				valid_hostname = True
			else:
				self.logger.info('Host %s not found, nothing to delete.', host)

		if do_write and valid_hostname:
			self.write_hosts()

	def write_hosts(self):
		''' write local hosts file, put it on the remote device '''

		self.logger.debug('Hosts entries:')
		for entry in self.hosts.entries:
			self.logger.debug(entry)

		self.logger.info('Writing local hosts file: %s', self.params.temp_file)
		self.hosts.write(path=self.params.temp_file)
		self.file_handler.put_hostfile()


class DockerHandler():
	''' Handle connecting to the Docker socket and the data it produces '''

	client = None

	def __init__(self, hosts_updater, **kwargs):
		self.params = SimpleNamespace(**kwargs)

		self.logger = get_logger(self.__class__.__name__, self.params.log_level)
		self.logger.debug('parameters:\n%s', json.dumps(vars(self.params), indent=4))

		self.hosts_updater = hosts_updater
		self.hostnames = []

		if self.params.ready_fd:
			self.ready_fd = int(self.params.ready_fd)
		else:
			self.ready_fd = False

	def get_client(self):
		''' create the Docker client object '''

		self.logger.debug('docker socket: %s', self.params.docker_socket)
		try:
			self.client = docker.DockerClient(base_url=self.params.docker_socket)
		except docker.errors.DockerException as err:
			self.logger.error('Could not open Docker socker. Halting.')
			self.logger.debug('Error: %s', err)
			sys.exit(1)
		else:
			self.logger.info('Connected to Docker socket.')

	def get_hostnames(self, container):
		''' return a list of hostnames for a container '''

		hostnames = [container.attrs['Config']['Hostname']]
		labels = container.labels
		extra_hosts = container.attrs['HostConfig']['ExtraHosts']
		self.logger.debug('extra_hosts: %s', extra_hosts)
		if extra_hosts:
			hostnames.append(extra_hosts)

		try:
			hostnames.append(labels['dnsmasq.updater.host'])
		except KeyError:
			pass

		for key, value in labels.items():
			if key.startswith('traefik.http.routers.'):
				hostnames.append(value[value.index('(`')+len('(`'):value.index('`)')])

		self.logger.debug('Found hostnames: %s', hostnames)

		return hostnames

	def scan_runnning_containers(self):
		''' scan all running containers and find any with dnsmasq.updater.enable '''

		self.logger.info('Started scanning running containers.')

		containers = self.client.containers.list(
			filters={"label":"dnsmasq.updater.enable=true", "status":"running"})

		for container in containers:
			names = self.get_hostnames(container)
			self.logger.info('Found %s: %s', container.name, names)
			self.hostnames.append(names)

		self.logger.info('Finished scanning running containers.')

	def scan_network_containers(self):
		''' scan all containers on a specified network '''

		self.logger.info('Started scanning containers on \'%s\' network.', self.params.network)
		try:
			network = self.client.networks.get(self.params.network)
		except docker.errors.NotFound:
			self.logger.error('Cannot scan network: network \'%s\' does not exist.', self.params.network)
			return

		for container in network.containers:
			names = self.get_hostnames(container)
			self.logger.info('Found %s: %s', container.name, names)
			self.hostnames.append(names)

		self.logger.info('Finished scanning containers on \'%s\' network.', self.params.network)

	def handle_event(self, event):
		''' monitor the docker socket for events '''

		# trigger on network connect/disconnect
		if (event['Type'] == 'network') and \
			(self.params.network in event['Actor']['Attributes']['name']) and \
			(event['Action'] in {'connect', 'disconnect'}):

			try:
				container = self.client.containers.get(event['Actor']['Attributes']['container'])
			except docker.errors.NotFound:
				self.logger.warning('Container %s not found.', event['Actor']['Attributes']['container'])
				container = None

			if container is not None:
				network = event['Actor']['Attributes']['name']
				names = self.get_hostnames(container)
				self.logger.debug('gotten hostnames: %s', names)

				if event['Action'] in 'connect':
					self.logger.info('Detected %s connecting to \'%s\' network. (%s)', \
						container.name, network, names)
					self.hosts_updater.add_host(names, do_write=True)
				elif event['Action'] in 'disconnect':
					self.logger.info('Detected %s disconnecting from \'%s\' network. (%s)', \
						container.name, network, names)
					self.hosts_updater.del_host(names, do_write=True)

		# trigger on container start
		elif (event['Type'] == 'container') and (event['status'] in {'start', 'stop'}) \
			and ('dnsmasq.updater.enable' in event['Actor']['Attributes']):

			container = self.client.containers.get(event['Actor']['ID'])
			names = self.get_hostnames(container)
			self.logger.debug('gotten hostname: %s', names)

			if event['status'] == 'start':
				self.logger.info('Detected %s starting. (%s)', container.name, names)
				self.hosts_updater.add_host(names, do_write=True)
			if event['status'] == 'stop':
				self.logger.info('Detected %s stopping. (%s)', container.name, names)
				self.hosts_updater.del_host(names, do_write=True)

	def run(self):
		''' connect to Docker socket, process existing containers then monitor events '''

		self.get_client()

		self.scan_runnning_containers()
		if self.params.network:
			self.scan_network_containers()

		self.hosts_updater.add_hosts(self.hostnames, do_write=True)

		if self.ready_fd:
			self.logger.info('Initialization done. Signalling readiness.')
			self.logger.debug('Readiness signal written to file descriptor %s.', self.ready_fd)
			write(self.ready_fd, '\n'.encode())
		else:
			self.logger.debug('Ready but signalling disabled.')

		events = self.client.events(decode=True)

		while True:
			for event in events:
				self.handle_event(event)


class ConfigHandler():
	''' read config files and parse commandline arguments '''

	log_level = DEFAULT_LOG_LEVEL

	def __init__(self):
		# setup default configuration
		self.defaults = {
			'config_file':CONFIG_FILE,
			'domain':'docker',
			'docker_socket':'unix://var/run/docker.sock',
			'network':'',
			'server':'',
			'port':'22',
			'login':'',
			'password':'',
			'key':'',
			'file':'',
			'remote_cmd':'',
			'temp_file':'/run/dnsmasq-updater/hosts.temp',
			'log_level':self.log_level,
			'ready_fd':False
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
		''' just enough argparse to specify a config file and a debug flag '''

		self.config_parser.add_argument(
			'-c', '--config_file', action='store', metavar='FILE',
			help='external configuration file')
		self.config_parser.add_argument(
			'--debug', action='store_true',
			help='turn on debug messaging')

		self.args = self.config_parser.parse_known_args()[0]

		if self.args.debug:
			self.log_level = logging.DEBUG
			self.defaults['log_level'] = logging.DEBUG

		self.logger = get_logger(self.__class__.__name__, self.log_level)

		self.logger.debug('Initial args: %s', json.dumps(vars(self.args), indent=4))

	def parse_config_file(self):
		''' find and read external configuration files, if they exist '''

		self.logger.debug('self.args.config_file: %s', self.args.config_file)

		# find external configuration if none is specified
		if self.args.config_file is None:
			for config_path in CONFIG_PATHS:
				config_file = path.join(config_path, CONFIG_FILE)
				self.logger.debug('Looking for config file: %s', config_file)
				if path.isfile(config_file):
					self.logger.info('Found config file: %s', config_file)
					self.args.config_file = config_file
					break

		if self.args.config_file is None:
			self.logger.info('No config file found.')

		# read external configuration if found or specified
		if self.args.config_file is not None:
			if path.isfile(self.args.config_file):
				config = configparser.ConfigParser()
				config.read(self.args.config_file)
				self.defaults.update(dict(config.items("dns")))
				self.defaults.update(dict(config.items("local")))
				self.defaults.update(dict(config.items("remote")))
				self.defaults.update(dict(config.items("docker")))
				self.logger.debug('Args from config file: %s', json.dumps(self.defaults, indent=4))
			else:
				self.logger.error('Config file (%s) does not exist.', self.args.config_file)

	def parse_command_line(self):
		''' parse command line arguments, overwriting both default config
			and anything found in a config file '''

		parser = argparse.ArgumentParser(
			description='Docker Dnsmasq Updater', parents=[self.config_parser])
		parser.set_defaults(**self.defaults)
		parser.add_argument(
			'-i', '--ip', action='store', metavar='IP',
			help='IP for the DNS record')
		parser.add_argument(
			'-d', '--domain', action='store', metavar='DOMAIN',
			help='domain/zone for the DNS record (default \'%(default)s\')')
		parser.add_argument(
			'-D', '--docker_socket', action='store', metavar='SOCKET',
			help='path to the docker socket (default \'%(default)s\')')
		parser.add_argument(
			'-n', '--network', action='store', metavar='NETWORK',
			help='Docker network to monitor')
		parser.add_argument(
			'-s', '--server', action='store', metavar='SERVER',
			help='dnsmasq server address')
		parser.add_argument(
			'-P', '--port', action='store', metavar='PORT',
			help='port for SSH on the dnsmasq server (default \'%(default)s\')')
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
			'-t', '--temp_file', action='store', metavar='FILE',
			help='the local file (including path) for temporary hosts file ' \
			'(default \'%(default)s\')')
		parser.add_argument(
			'--ready_fd', action='store', metavar='INT',
			help='set to an integer file descriptor to enable signalling readiness ' \
			'by writing a new line to that file descriptor (default \'%(default)s\')')
		self.args = parser.parse_args()

		self.logger.debug('Parsed command line:\n%s', json.dumps(vars(self.args), indent=4))

	def check_args(self):
		''' Check we have all the information we need to run '''

		if self.args.login == '':
			self.logger.error('No login name specified.')
			sys.exit(1)

		if self.args.key == '':
			if self.args.password == '':
				self.logger.error('No password or key specified.')
				sys.exit(1)
		else:
			if not path.exists(self.args.key):
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
			sys.exit(1)

	def get_args(self):
		''' return all config parameters '''

		return self.args


def main():
	''' do all the things '''

	config = ConfigHandler()
	args = config.get_args()
	file_handler = FileHandler(**vars(args))
	hosts_updater = HostsHandler(file_handler, **vars(args))
	docker_handler = DockerHandler(hosts_updater, **vars(args))
	docker_handler.run()

if __name__ == '__main__':
	main()
