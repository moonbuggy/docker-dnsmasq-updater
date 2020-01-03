# Docker Dnsmasq Updater
Automatically update a remote hosts file with Docker container hostnames

## Rationale

If you have a LAN with your router using dnsmasq for local DNS you may find yourself frequently updating a hosts file as you add or remove Docker containers. The currently available options for automating this typically require you to put Docker containers in a subdomain (e.g. *.docker.local) and/or, if you want to keep the containers in the top level domain (e.g. *.local), installing a full-fledged name server on the router and syncing it with the same in a container on the Docker host.

Docker Dnsmasq Updater allows host names to be added or removed automatically without added complexity or resource demands on the router. It can be run as a standalone script on the Docker host or in a container, it only needs access to the Docker socket and SSH access to the router (or any device providing local DNS with a hosts file).

This script has been built with an AsusWRT/Entware router in mind, but should work with any device running dnsmasq or using a hosts file.

## What It Does

- Runs on the Docker host OR in a container
- On load, scans all running containers for a `dnsmasq.updater.enable` label
- Optionally, on load, scans a specified network for running containers
- After loading, monitors the Docker socket for containers starting/stopping and optionally connecting/disconnecting to a specified network
- Finds any hostnames for containers meeting criteria
- Updates a remote hosts file
- Restarts a remote dnsmasq server

Currently the updater is built for a standalone Docker host. It only allows one IP to be specified for any host it finds.

## Usage

```
usage: dnsmasq_updater.py [-h] [-c FILE] [--debug] [-i IP] [-d DOMAIN]
                          [-D PATH] [-n NETWORK] [-s SERVER] [-P PORT]
                          [-l USERNAME] [-k FILE] [-p PASSWORD] [-f FILE]
                          [-r COMMAND] [-t FILE] [--ready_fd INT]

Docker Dnsmasq Updater

optional arguments:
  -h, --help            show this help message and exit
  -c FILE, --config_file FILE
                        external configuration file
  --debug               turn on debug messaging
  -i IP, --ip IP        IP for the DNS record
  -d DOMAIN, --domain DOMAIN
                        domain/zone for the DNS record (default 'docker')
  -D SOCKET, --docker_socket SOCKET
                        path to the docker socket (default
                        'unix://var/run/docker.sock')
  -n NETWORK, --network NETWORK
                        Docker network to monitor
  -s SERVER, --server SERVER
                        dnsmasq server address
  -P PORT, --port PORT  port for SSH on the dnsmasq server (default '22')
  -l USERNAME, --login USERNAME
                        login name for the dnsmasq server
  -k FILE, --key FILE   identity/key file for SSH to the dnsmasq server
  -p PASSWORD, --password PASSWORD
                        password for the dnsmasq server OR for an encrypted
                        SSH key
  -f FILE, --file FILE  the file (including path) to write on the dnsmasq
                        server
  -r COMMAND, --remote_cmd COMMAND
                        the update command to execute on the dnsmasq server
  -t FILE, --temp_file FILE
                        the local file (including path) for temporary hosts
                        file (default '/run/dnsmasq-updater/hosts.temp')
  --ready_fd INT        set to an integer file descriptor to enable signalling
                        readiness by writing a new line to that file
                        descriptor (default 'False')

```

Any command line parameters take precedence over settings in `dnsmasq_updater.conf`.

The SSH connection requires either a login/password combination or a login/key combination. If using a key that is encrypted any password parameter supplied will be used for the key, not the login name.

## Setup

Docker Dnsmasq Updater requires at least Python 3.4 and the docker, paramiko and python_hosts modules.

The script can be run standalone on the Docker host or in a Docker container, so long as it has access to the Docker socket it's happy.

You do not need to both install it on the host and run the container, it would in fact be a bad idea to do so. Choose one or the other, whichever you feel works best for you.

### Installation on Docker host

Install requirements: `pip3 install -r requirements.txt`

Put `dnsmasq_updater.py` anywhere in the path.

Put `dnsmasq_updater.conf` in `/etc/` or in the same directory as the script (which takes precedence over any config file in `/etc/`).

### Installation of Docker container

```
docker run -d --name dnsmasq-updater -v /var/run/docker.sock:/var/run/docker.sock moonbuggy2000/dnsmasq-updater
```

If you're using a config file instead of environment variables (see below) you'll need to persist it with `-v <conf volume>:/app/conf/dnsmasq_updater.conf`. If you're using an SSH key for authentication you can persist and use the `/app/keys/` folder.

#### Tags

To minimize the Docker image size, and to theoretically improve run times (I haven't benchmarked it because I believe it runs fast enough either way), the default build is binary, tagged as `latest` and `binary`.

A build using the uncompiled Python script is available, tagged `script`.

#### Docker environment variables

Almost all the command line parameters (see Usage) can be set with enviornment variables:

* `DMU_IP`          - IP for the DNS records
* `DMU_DOMAIN`      - domain/zone for the DNS records, defaults to `docker`
* `DMU_NETWORK`     - Docker network to monitor, defaults to none/disabled
* `DMU_SERVER`      - dnsmasq server address
* `DMU_PORT`        - dnsmasq server SSH port, defaults to `22`
* `DMU_LOGIN`       - dnsmasq server login name
* `DMU_PASSWORD`    - password for the login name or, if a key is specified, decryption of the key
* `DMU_KEY`         - full path to SSH key file
* `DMU_REMOTE_FILE` - full path to the hosts file to update on the dnsmasq server
* `DMU_REMOTE_CMD`  - remote command to execute to restart/update dnsmasq, defaults to `service restart_dnsmasq`
* `DMU_DEBUG`       - set `True` to enable debug log output

### Setup on dnsmasq server

If you have an external storage device attached to your router it makes sense to keep the hosts file the updater generates there, to minimize writes to the router's onboard storage.

As an example, if you're using AsusWRT/Entware you can easily configure the router to include this external file by writing to `/opt/etc/hosts` and adding the following to `/jffs/scripts/hosts.postconf`:

```
# for remote hosts updates
if [ -f /opt/etc/hosts ]; then
  cat "/opt/etc/hosts" >> "$CONFIG"
fi
```

As dnsmasq may start before `/opt` is mounted dnsmasq should be restarted in `/jffs/scripts/post-mount`, to ensure container name resolution functions after a router reboot:

```
if [ -d "$1/entware" ] ; then
  ln -nsf $1/entware /tmp/opt

  service restart_dnsmasq
fi
```

Relevant configuration parameters for Docker Dnsmasq Updater in this scenario would be `--remote_file /opt/etc/hosts --remote_cmd 'service restart_dnsmasq'`.

If you're using a key instead of a password you'll need to add the appropriate public key to `~/.ssh/authorized_keys` on the router.

### Setup for other Docker containers

To enable Docker Dnsmasq Updater for an individual container there are two labels that can be set:

* `dnsmasq.updater.enable` - set this to "true"
* `dnsmasq.updater.host`   - set this to the hostname you want to use

The updater will also add `hostname` and any `extra_hosts` attributes set for a container, so `dnsmasq.updater.host` isn't strictly necessary if hostnames are set as you want them for a container elsewhere.

If you choose to monitor a user-defined Docker network then `dnsmasq.updater.enable` isn't strictly necessary either. The udpater assumes any container connecting to the monitored network is a container that you want working DNS for.

### Use with Traefik

Docker Dnsmasq Updater will pull Traefik hostnames set on containers via the ``traefik.http.routers.<router>.rule=Host(`<host>`)`` label. 

As all containers joining a monitored network are considered valid, if you monitor a user-defined network that Traefik uses you don't need to set any `dnsmasq.updater` enviornment variables at all, it gets what it needs from the network and Traefik environment variables.

This scenario provides the easiest/laziest configuration route, with no Docker Dnsmasq Updater specific cofiguration required on containers.

## Links

GitHub: https://github.com/moonbuggy/docker-dnsmasq-updater

Docker Hub: https://hub.docker.com/r/moonbuggy2000/dnsmasq-updater
