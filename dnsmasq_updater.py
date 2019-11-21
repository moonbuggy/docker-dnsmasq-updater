#!/usr/bin/env python3

'''
Docker Dnsmasq Updater

Use the Docker socket to update a remote dnsmasq server with container hostnames
'''

from os import curdir, path, makedirs
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
from scp import SCPClient, SCPException
import requests

## list possible configuration file locations in the order they should
## be tried, use first match
CONFIG_FILE = 'dnsmasq_updater.conf'
CONFIG_PATHS = [curdir, '/etc/', '/conf/']

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

		self.ssh = SSHClient()
		self.ssh.set_missing_host_key_policy(AutoAddPolicy())

		self.get_server_ip()

		if self.params.key != '':
			self.verify_key()

		self.get_clean_hosts()

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
				sys.exit()

	def verify_key(self):
		''' verify and open key file or error on failure '''

		try:
			self.logger.debug('Testing if key is RSA.')
			self.key = RSAKey.from_private_key_file(self.params.key)
			self.logger.info('Found valid RSA key.')
		except PasswordRequiredException:
			if self.params.password != '':
				try:
					self.logger.debug('Decrypting RSA key.')
					self.key = RSAKey.from_private_key_file(self.params.key, password=self.params.password)
					self.logger.info('Found valid encrypted RSA key.')
				except SSHException:
					self.logger.error('Password for key is not valid.')
					sys.exit()
			else:
				self.logger.error('Encrypted RSA key, requires password.')
				sys.exit()
		except SSHException:
			try:
				self.logger.debug('Testing if key is DSA.')
				self.key = DSSKey.from_private_key_file(self.params.key)
				self.logger.info('Found valid DSA key.')
			except PasswordRequiredException:
				if self.params.password != '':
					try:
						self.logger.debug('Decrypting DSA key.')
						self.key = DSSKey.from_private_key_file(self.params.key, password=self.params.password)
						self.logger.info('Found valid encrypted DSA key.')
					except SSHException:
						self.logger.error('No valid password for DSA key.')
						sys.exit()
				else:
					self.logger.error('Encrypted DSA key, requires password.')
					sys.exit()
			except SSHException:
				self.logger.error('Key is not valid RSA or DSA.')
				sys.exit()


	def open_ssh(self):
		''' connect to the remote device '''

		try:
			if self.params.key != '':
				self.ssh.connect(
					self.params.server_ip,
					username=self.params.login,
					pkey=self.key)
			else:
				self.ssh.connect(
					self.params.server_ip,
					username=self.params.login,
					password=self.params.password)

		except AuthenticationException:
			self.logger.error('Could not authenticate with remote device.')
			sys.exit()

	def open_scp(self):
		''' prepare SCP to use SSH transport '''

		self.open_ssh()
		self.scp = SCPClient(self.ssh.get_transport())

	def close_scp(self):
		''' close the SCP and SSH connections '''

		self.scp.close()
		self.ssh.close()

	def get_hostfile(self):
		''' get the specified hosts file from the remote device '''

		self.logger.info('Downloading remote hosts file: %s', self.params.file)
		self.open_scp()
		try:
			self.scp.get(self.params.file, local_path=self.params.temp_file)
		except SCPException:
			self.logger.error('Remote hosts file does not exist.')
			sys.exit()
		self.close_scp()

	def put_hostfile(self):
		''' put the local hosts file on the remote device '''

		self.logger.info('Uploading remote hosts file: %s', self.params.file)
		self.open_scp()
		self.scp.put(self.params.temp_file, remote_path=self.params.file)
		self.close_scp()
		self.exec_command()

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

	def exec_command(self):
		''' execute command to update dnsmasq on remote device '''

		self.open_ssh()
		try:
			self.ssh.exec_command(self.params.remote_cmd)
			self.logger.info('Restarted dnsmasq on remote device.')
		except SSHException:
			self.logger.error('Failed to execute remote command: %s', self.params.remote_cmd)
		self.ssh.close()

class HostsHandler():
	''' Handle the Hosts object and the individual HostEntry objects '''

	def __init__(self, file_handler, zone, ip_addr, temp_file, log_level):
		self.logger = get_logger(self.__class__.__name__, log_level)

		self.file_handler = file_handler
		self.zone = zone
		self.ip_addr = ip_addr
		self.temp_file = temp_file

		self.block_start = file_handler.block_start

		self.hosts = Hosts(path=self.temp_file)
		if not self.hosts.exists(comment=self.block_start):
			comment = HostsEntry(entry_type='comment', comment=self.block_start)
			self.hosts.add([comment], force=True, allow_address_duplication=True)

	def parse_hostnames(self, hostnames):
		''' return a list of hostnames with and without the zone attached on each '''

		parsed_hostnames = []

		for hostname in hostnames:
			try:
				hostname = hostname[0:hostname.index('.' + self.zone)]
			except ValueError:
				pass

			zoned_name = hostname + '.' + self.zone
			if (zoned_name) not in parsed_hostnames:
				parsed_hostnames.append(zoned_name)

			if hostname not in parsed_hostnames:
				parsed_hostnames.append(hostname)

		return parsed_hostnames

	def add_hosts(self, hosts_list, write=False):
		''' iterate through a list of hosts, add each host's names individually '''

		for hostnames in hosts_list:
			self.add_host(hostnames)

		if write:
			self.write_hosts()

	def add_host(self, hostnames, write=False):
		''' create HostsEntry for a host and at it to Hosts object, optionally write out '''

		do_add = False

		names = self.parse_hostnames(hostnames)
		for name in names:
			if not self.hosts.exists(names=[name]):
				do_add = True
				break

		if do_add:
			hostentry = HostsEntry(entry_type='ipv4', address=self.ip_addr, names=names)
			self.hosts.add([hostentry], force=True, allow_address_duplication=True)

			self.logger.info('Added host: %s', names)

			if write:
				self.write_hosts()
		else:
			self.logger.info('Host already exists, skipping: %s', names)

	def del_hosts(self, hosts_list, write=False):
		''' iterate through a list hosts, delete each host's names individually '''

		self.logger.debug('del_hosts hosts_list: %s', hosts_list)
		for hosts in hosts_list:
			self.logger.debug('del_hosts: %s', hosts)

		if write:
			self.write_hosts()

	def del_host(self, hostnames, write=False):
		''' delete a host's names, optionally write out '''

		do_write = False

		self.logger.debug('del_host: %s', hostnames)
		for host in hostnames:
			if self.hosts.exists(names=[host]):
				self.hosts.remove_all_matching(name=host)
				self.logger.info('Deleted hosts: %s', hostnames)
				if write:
					do_write = True
			else:
				self.logger.info('Host %s not found, nothing to delete.', host)

		if do_write:
			self.write_hosts()

	def write_hosts(self):
		''' write local hosts file, put it on the remote device '''

		self.logger.debug('Hosts entries:')
		for entry in self.hosts.entries:
			self.logger.debug(entry)

		self.logger.info('Writing local hosts file: %s', self.temp_file)
		self.hosts.write(path=self.temp_file)
		self.file_handler.put_hostfile()


class DockerHandler():
	''' Handle connecting to the Docker socket and the data it produces '''

	client = None

	def __init__(self, hosts_updater, network, log_level):
		self.logger = get_logger(self.__class__.__name__, log_level)

		self.hosts_updater = hosts_updater
		self.network = network

		self.hostnames = []

	def get_client(self):
		''' create the Docker client object '''

		self.client = docker.from_env()
		try:
			self.client.ping()
		except requests.exceptions.ConnectionError:
			self.logger.error('Could not open Docker socket.')
			sys.exit()

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

		self.logger.info('Started scanning containers on \'%s\' network.', self.network)
		try:
			network = self.client.networks.get(self.network)
		except docker.errors.NotFound:
			self.logger.error('Cannot scan network: network \'%s\' does not exist.', self.network)
			return

		for container in network.containers:
			names = self.get_hostnames(container)
			self.logger.info('Found %s: %s', container.name, names)
			self.hostnames.append(names)

		self.logger.info('Finished scanning containers on \'%s\' network.', self.network)

	def handle_event(self, event):
		''' monitor the docker socket for events '''

		# trigger on network connect/disconnect
		if (event['Type'] == 'network') and \
			(self.network in event['Actor']['Attributes']['name']) and \
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
					self.hosts_updater.add_host(names, write=True)
				elif event['Action'] in 'disconnect':
					self.logger.info('Detected %s disconnecting from \'%s\' network. (%s)', \
						container.name, network, names)
					self.hosts_updater.del_host(names, write=True)

		# trigger on container start
		elif (event['Type'] == 'container') and (event['status'] in {'start', 'stop'}) \
			and ('dnsmasq.updater.enable' in event['Actor']['Attributes']):
			container = self.client.containers.get(event['Actor']['ID'])
			print(json.dumps(event, indent=4))
			if container.labels['dnsmasq.updater.enable']:
				print('SHOULD ABORT HERE')
			names = self.get_hostnames(container)
			self.logger.debug('gotten hostname: %s', names)

			if event['status'] == 'start':
				self.logger.info('Detected %s starting. (%s)', container.name, names)
				self.hosts_updater.add_host(names, write=True)
			if event['status'] == 'stop':
				self.logger.info('Detected %s stopping. (%s)', container.name, names)
				self.hosts_updater.del_host(names, write=True)

	def run(self):
		''' connect to Docker socket, process existing containers then monitor events '''

		self.get_client()

		self.scan_runnning_containers()
		if self.network:
			self.scan_network_containers()

		self.hosts_updater.add_hosts(self.hostnames, write=True)

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
			'network':'',
			'server':'',
			'port':'22',
			'login':'',
			'password':'',
			'key':'',
			'file':'/opt/etc/hosts',
			'remote_cmd':'service restart_dnsmasq',
			'temp_file':'/run/dnsmasq-updater/hosts.temp',
			'log_level':self.log_level
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
			'-n', '--network', action='store', metavar='NETWORK',
			help='Docker network to monitor')
		parser.add_argument(
			'-s', '--server', action='store', metavar='SERVER',
			help='dnsmasq server address')
		parser.add_argument(
			'-P', '--port', action='store', metavar='PORT',
			help='port for SSH/SCP on the dnsmasq server (default \'%(default)s\')')
		parser.add_argument(
			'-l', '--login', action='store', metavar='USERNAME',
			help='login name for the dnsmasq server')
		parser.add_argument(
			'-k', '--key', action='store', metavar='FILE',
			help='identity/key file for SSH/SCP to the dnsmasq server')
		parser.add_argument(
			'-p', '--password', action='store', metavar='PASSWORD',
			help='password for the dnsmasq server OR for an encrypted SSH key')
		parser.add_argument(
			'-f', '--file', action='store', metavar='FILE',
			help='the file (including path) to write on the dnsmasq server')
		parser.add_argument(
			'-r', '--remote_cmd', action='store', metavar='COMMAND',
			help='the update command to execute on the dnsmasq server '\
			' (default \'%(default)s\')')
		parser.add_argument(
			'-t', '--temp_file', action='store', metavar='FILE',
			help='the local file (including path) for temporary hosts file ' \
			'(default \'%(default)s\')')
		self.args = parser.parse_args()

		self.logger.debug('Parsed command line:\n%s', json.dumps(vars(self.args), indent=4))

	def check_args(self):
		''' Check we have all the information we need to run '''

		if self.args.login == '':
			self.logger.error('No login name specified.')
			sys.exit()

		if self.args.key == '':
			if self.args.password == '':
				self.logger.error('No password or key specified.')
				sys.exit()
		else:
			if not path.exists(self.args.key):
				self.logger.error('Key file (%s) does not exist.', self.args.key)
				sys.exit()

		if self.args.ip == '':
			self.logger.error('No host IP specified.')
			sys.exit()
		else:
			try:
				ipaddress.ip_address(self.args.ip)
			except ValueError:
				self.logger.error('Specified host IP (%s) is invalid.', self.args.ip)
				sys.exit()

		if self.args.server == '':
			self.logger.error('No remote server specified.')
			sys.exit()

		if self.args.file == '':
			self.logger.error('No remote file specified.')
			sys.exit()

		if not path.exists(path.dirname(self.args.temp_file)):
			try:
				makedirs(path.dirname(self.args.temp_file))
			except OSError as err:
				if err.errno != errno.EEXIST:
					backup_temp_file = '/tmp/dnsmasq-updater.temp'
					self.logger.warning(
						'Cannot create folder for specified temporary file (\'%s\'), ' \
						'defaulting to \'%s\'', self.args.temp_file, backup_temp_file)
					self.args.temp_file = backup_temp_file

	def get_args(self):
		''' return all config parameters '''

		return self.args


def main():
	''' do all the things '''

	config = ConfigHandler()
	args = config.get_args()
	file_handler = FileHandler(**vars(args))
	hosts_updater = HostsHandler(file_handler, args.domain, args.ip, args.temp_file, args.log_level)
	docker_handler = DockerHandler(hosts_updater, args.network, args.log_level)
	docker_handler.run()

if __name__ == '__main__':
	main()
