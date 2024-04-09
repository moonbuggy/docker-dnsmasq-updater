<!--lint disable no-undefined-references no-shortcut-reference-link-->

# Docker Dnsmasq Updater
Automatically update a local or remote hosts file with Docker container hostnames.

*   [Rationale](#rationale)
*   [What It Does](#what-it-does)
*   [Usage](#usage)
    *   [Standalone/Manager](#standalonemanager)
    *   [Swarm mode](#swarm-mode)
*   [Setup](#setup)
    *   [Installation on Docker host](#installation-on-docker-host)
    *   [Installation of Docker container(s)](#installation-of-docker-containers)
    *   [Setup on dnsmasq server](#setup-on-dnsmasq-server)
    *   [Setup for other Docker containers](#setup-for-other-docker-containers)
    *   [Use with Traefik](#use-with-traefik)
*   [Known Issues](#known-issues)
*   [Links](#links)

## Rationale
If you have a LAN with your router using _dnsmasq_ for local DNS you may find
yourself frequently updating a hosts file as you add or remove Docker containers.
The currently available options for automating this typically require you to put
Docker containers in a subdomain (e.g. \*.docker.local) and/or, if you want to
keep the containers in the top level domain (e.g. \*.local), installing a
full-fledged name server on the router and syncing it with the same in a
container on the Docker host.

Docker Dnsmasq Updater allows hostnames to be added or removed automatically
without added complexity or resource demands on the router. It can be run as a
standalone script or in a container, it only needs access to the Docker socket
and SSH access to the router (or any device providing local DNS with a hosts
file).

This script has been built with an [AsusWRT-Merlin][]/[Entware][] router in
mind, but should work with any device running _dnsmasq_ or using a hosts file.

## What It Does
-   Runs on the Docker host OR in a container OR anywhere (in manager mode)
-   On load, scans all running containers for a `dnsmasq.updater.enable` label
-   Optionally, on load, scans a specified Docker network for running containers
-   After loading, monitors the Docker socket for containers starting/stopping
    and optionally connecting/disconnecting to a specified Docker network
-   Finds any hostnames for containers meeting criteria
-   Writes a hosts file
-   Restarts a _dnsmasq_ daemon

## Usage
### Standalone/Manager
```
usage: dnsmasq_updater.py [-h] [-c FILE] [--debug] [--ready_fd INT]
                          [--standalone | --manager] [-D SOCKET] [-n NETWORK] [-i IP]
                          [-d DOMAIN] [-w] [--remote | --local] [-f FILE]
                          [-r COMMAND] [-t SECONDS] [-s SERVER] [-P PORT]
                          [-l USERNAME] [-k FILE] [-p PASSWORD] [--api_port PORT]
                          [--api_key KEY]

Docker Dnsmasq Updater

options:
  -h, --help            show this help message and exit
  -c FILE, --config_file FILE
                        external configuration file
  --debug               turn on debug messaging
  --ready_fd INT        set to an integer to enable signalling readiness by writing
                        a new line to that integer file descriptor

Mode:
  --standalone          running on a standalone Docker host (default)
  --manager             bring up the API and run as the manager for multiple
                        Docker nodes

Docker:
  -D SOCKET, --docker_socket SOCKET
                        path to the docker socket (default:
                        'unix://var/run/docker.sock')
  -n NETWORK, --network NETWORK
                        Docker network to monitor

DNS:
  -i IP, --ip IP        default IP for the DNS records
  -d DOMAIN, --domain DOMAIN
                        domain/zone for the DNS record (default: 'docker')
  -w, --prepend_www     add 'www' subdomains for all hostnames

hosts file:
  --remote              write to a remote hosts file, via SSH (default)
  --local               write to a local hosts file
  -f FILE, --file FILE  the hosts file (including path) to write
  -r COMMAND, --restart_cmd COMMAND
                        the dnsmasq restart command to execute
  -t SECONDS, --delay SECONDS
                        delay for writes to the hosts file (default: '10')

Remote hosts file (needed by --remote):
  -s SERVER, --server SERVER
                        dnsmasq server address
  -P PORT, --port PORT  port for SSH on the dnsmasq server (default: '22')
  -l USERNAME, --login USERNAME
                        login name for the dnsmasq server
  -k FILE, --key FILE   identity/key file for SSH to the dnsmasq server
  -p PASSWORD, --password PASSWORD
                        password for the dnsmasq server OR for an encrypted SSH key

API server (needed by --manager):
  --api_address PORT    address for API to listen on (default: '0.0.0.0')
  --api_port PORT       port for API to listen on (default: '8080')
  --api_key KEY         API access key
  --api_backend STRING  API backend (refer to Bottle module docs for details)
```

Any command line parameters take precedence over settings in _dnsmasq_updater.conf_.

The SSH connection requires either a login/password combination or a login/key
combination. If using a key that is encrypted any password parameter supplied
will be used for the key, not the login name.

The write delay (`--delay`) is useful because in some cases we expect to see
multiple events in reasonably rapid succession, such as when a container is
re-started or multiple containers are started together as part of a stack. The
remote hosts file will be updated _\<delay> seconds_ after the last change to
the script's local copy of the hosts file. Set this to `0` to disable the delay.

There's a hidden `--local_write_delay` argument, similar to `--delay`, which
mediates the delay between a Docker event triggering a change and the script's
local copy of the hosts file being written. This is useful during extremely
rapid changes to the hosts configuration, primarily during Dnsmasq Updater's
startup/initialization as it actively scans for containers to populate an empty
dataset. This defaults to `3` and can be disabled by `0`.

### Swarm mode
To operate sensibly in a Docker Swarm it's necessary to adopt a manager/agent
configuration, with a single global manager instance being updated through an
API by agents running on each Swarm node.

The main _dnsmasq_updater.py_ script will not run in a Swarm environment in
the default `--standalone` mode. Manager mode must be enabled with the
`--manager` argument on the command line or the `mode` value in the config file.

Conversely, the Agent _will_ run on standalone Docker hosts, so it's possible to
run multiple standalone hosts (as well as Swarms) through a single manager
instance.

In manager mode the script won't listen to the Docker socket directly, only
ingesting API data. Agents need to be running on all devices in the Swarm to
catch all relevant container and network activity.

The manager instance can run anywhere, it doesn't need to be in the Swarm, so
long as the Agents can access the API. If desired, the manager script can be
run on the device running _dnsmasq_, using the `--local` argument to write to a
hosts file on the local system.

#### Agent usage
The Agent is a separate script, _dnsmasq_updater_agent.py_, to remove unnecessary
overhead and minimize resource demands on the Swarm nodes. Configuration is
similar to the main script, we're just aiming at the API of a manager instance
instead of a remote SSH server.

```
usage: dnsmasq_updater_agent.py [-h] [-c FILE] [--debug] [-D SOCKET] [-n NETWORK]
                                [-s SERVER] [-P PORT] [-k KEY] [-R SECONDS]
                                [--ready_fd INT]

Docker Dnsmasq Updater Agent

options:
  -h, --help            show this help message and exit
  -c FILE, --config_file FILE
                        external configuration file
  --debug               turn on debug messaging
  --ready_fd INT        set to an integer to enable signalling readiness by
                        writing a new line to that integer file descriptor

Docker:
  -D SOCKET, --docker_socket SOCKET
                        path to the docker socket (default: 'unix://var/run/docker.sock')
  -n NETWORK, --network NETWORK
                        Docker network to monitor

API:
  -s SERVER, --api_server SERVER
                        API server address
  -P PORT, --api_port PORT
                        API server port (default: '8080')
  -k KEY, --api_key KEY
                        API access key
  -R SECONDS, --api_retry SECONDS
                        delay before retrying failed connection (default: '10')
  -t SECONDS, --api_check SECONDS
                        delay between checking the API server status (default: '60')
  --clean_on_exit, --no-clean_on_exit
                        delete this device's hosts from the API when the Agent
                        shuts down (default: enabled)
```
The `--api_key` argument is a string and needs to match the same on the manager.

## Setup
Docker Dnsmasq Updater requires at least Python 3.10 and the _bottle_,
_bottlejwt_, _docker_, _paramiko_ and _python_hosts_ modules.

Docker Dnsmasq Updater Agent requires only the _docker_ module.

In the default `--standalone` mode the script can be run on a standalone Docker
host, either directly or in a container. So long as it has access to the Docker
socket it's happy.

You do not need to both install it on the host and run the container, it would
in fact be a bad idea to do so. Choose one or the other, whichever you feel
works best for you.

In `--manager` mode the script can be run anywhere that's reachable from the
Agents, they just need to be able to see the API. If running the API with a
backend set by `--api_backend` (rather than using Bottle directly), that
backend's module will need to be installed.

If running on the same device as _dnsmasq_, the `--local` argument allows
writing the hosts file directly to the local filesystem.

### Installation on Docker host
Install requirements: `pip3 install -r requirements.txt`

Put _dnsmasq_updater.py_ anywhere in the path.

Put _dnsmasq_updater.conf_ in `/etc/` or in the same directory as the script
(which takes precedence over any config file in `/etc/`).

### Installation of Docker container(s)
#### Standalone deployment
```sh
docker run -d \
  --name dnsmasq-updater \
  -v /var/run/docker.sock:/var/run/docker.sock \
  moonbuggy2000/dnsmasq-updater
```

If you're using a config file instead of environment variables (see below)
you'll need to persist it with `-v <host path>:/app/conf/dnsmasq_updater.conf`.
If you're using an SSH key for authentication you can persist and use the
_/app/keys/_ folder.

#### Swarm deployment
##### docker-compose.yml
```yaml
version: '3.8'

services:
  dnsmasq-updater:
    image: moonbuggy2000/dnsmasq-updater:script
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          # use a label to choose a specific Swarm node for the manager
          # this ensures the volume for /app/keys will be present
          - node.labels.dnsmasq-updater == true
    hostname: dmu.swarm
    environment:
      - DMU_DEBUG=false
      - DMU_MODE=manager
      - DMU_DOMAIN=swarm
      - DMU_IP=<frontend_IP>
      - DMU_KEY=/app/keys/id_rsa
      - DMU_LOGIN=<login>
      - DMU_PREPEND_WWW=true
      - DMU_REMOTE_FILE=/opt/etc/hosts.swarm
      - DMU_SERVER=<dnsmasq_server_IP>
      - DMU_API_PORT=8080
      - DMU_API_KEY=<api_key>
    volumes:
      - dnsmasq-updater_keys:/app/keys
    networks:
      - traefik

  dnsmasq-updater-agent:
    image: moonbuggy2000/dnsmasq-updater:agent
    deploy:
      mode: global
    environment:
      - DMU_DEBUG=false
      - DMU_NETWORK=traefik
      - DMU_API_SERVER=dmu.swarm
      - DMU_API_PORT=8080
      - DMU_API_KEY=<api_key>
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
      - traefik

volumes:
  dnsmasq-updater_keys:
    name: dnsmasq-updater_keys

networks:
  traefik:
    external: true
```
This compose file assumes there's a pre-existing Traefik service and network.

Since, in this case, the Agents are all connecting to the _traefik_ network
to monitor it for activity, it's convenient to stick the manager on this network
as well and use it for API communication.

The manager's `DMU_IP` default IP should point to a frontend/reverse proxy,
Traefik or otherwise. It's possible to override the default IP on a
per-container basis with with a `dnsmasq.updater.ip` label on individual
containers.

To meet the manager's constraints, the `dnsmasq-updater.manager` label will need
to be applied to the to the chosen node:
<code>docker node update --label-add dnsmasq-updater.manager \<node\></code>

See below for a detailed description of available
[environment variables](#docker-environment-variables).

The Agent should be allowed to restart freely since, by design, it will exit
upon encountering a variety of otherwise non-fatal errors. This is a simple way
to trigger a fresh initialization and ensure the manager has the full picture if
it is restarted or communications are interrupted for whatever reason.

#### Image Tags
The default `latest` tag and the `script` tag point to the standalone/manager
script. Agent images will be tagged `agent`.

Tags may be prefixed with `<version>-` to get a specific version, or just use a
version number by itself to get `<version>-script`.

> [!NOTE]
> After upgrading the Nuitka version, binary builds are currently larger than the
> un-compiled images. There's also an issue building gunicorn (which is used as
> the API backend in the image) that I've not bothered investigating.
>
> As a result, for the time being at least, I've discontinued the `binary` builds.
> The build system remains capable of building them, and I may begin doing so
> again at some point. But not today.

#### Architectures
The main `latest`, `<version>`, `script`, and `agent` tags should automatically
provide images compatible with `amd64`, `arm`/`armv7`, `armhf`/`armv6`, `arm64`,
`386` and `ppc64le` platforms. Tags for specific single-arch images are
available, in the form `alpine-<arch>` and `agent-<arch>` for the respective
builds.

> [!NOTE]
> I'm only able to test on `amd64`, `armv7` and `arm64`. The `script` and `agent`
> images currently work on these architectures. I assume they work on other
> architectures as well, but can't guarantee it..

#### Docker environment variables
Almost all the command line parameters (see [Usage](#usage)) can be set with
environment variables.

##### Docker Dnsmasq Updater
*   `DMU_MODE`           - operation mode (accepts: _standalone_, _manager_; default: _standalone_)
*   `DMU_HOSTS_LOCATION` - location of hosts file (accepts: _local_, _remote_, default: _remote_)
*   `DMU_IP`             - default IP for the DNS records
*   `DMU_DOMAIN`         - domain/zone for the DNS records (default: _docker_)
*   `DMU_PREPEND_WWW`    - add _www_ subdomains to all hostnames (default: _False_)
*   `DMU_DOCKER_SOCKET`  - path to the docker socket (default: _unix://var/run/docker.sock_)
*   `DMU_NETWORK`        - Docker network to monitor, defaults to none/disabled
*   `DMU_SERVER`         - _dnsmasq_ server address
*   `DMU_PORT`           - _dnsmasq_ server SSH port (default: _22_)
*   `DMU_LOGIN`          - _dnsmasq_ server login name
*   `DMU_PASSWORD`       - password for the login name or, if a key is specified, decryption of the key
*   `DMU_KEY`            - full path to SSH key file
*   `DMU_HOSTS_FILE`     - full path to the hosts file to update on the _dnsmasq_ server
*   `DMU_RESTART_CMD`    - command to execute to restart/update dnsmasq (default _service restart_dnsmasq_)
*   `DMU_DELAY`          - delay (in seconds) before writing remote hosts file (default: _10_)
*   `DMU_API_ADDRESS`    - address for API to listen on (default: _0.0.0.0_)
*   `DMU_API_PORT`       - port for API to listen on (default: _8080_)
*   `DMU_API_KEY`        - API access key
*   `DMU_DEBUG`          - set _True_ to enable debug log output
*   `TZ`		             - set timezone

##### Docker Dnsmasq Updater Agent
*   `DMU_DOCKER_SOCKET`  - path to the docker socket (default: _unix://var/run/docker.sock_)
*   `DMU_NETWORK`        - Docker network to monitor (default: none/disabled)
*   `DMU_API_SERVER`     - API server address
*   `DMU_API_PORT`       - port the API is listening on (default: _8080_)
*   `DMU_API_KEY`        - API access key
*   `DMU_API_RETRY`      - delay (in seconds) before retrying failed connection (default: _10_)
*   `DMU_API_CHECK`      - delay (in seconds) between checking the API server status (default: _60_)
*   `DMU_CLEAN_ON_EXIT`  - delete this device's hosts from the API when the Agent shuts down (default: _True_)
*   `DMU_DEBUG`          - set _True_ to enable debug log output
*   `TZ`		             - set timezone

### Setup on dnsmasq server
Docker Dnsmasq Updater won't track changes other software (i.e _dnsmasq_) might
make to the hosts file. Thus, to avoid conflicts, it's best to give Docker
Dnsmasq Updater it's own hosts file to use and either specify it as an
additional hosts file to _dnsmasq_ (with the `-addn-hosts <file>` argument, or
in _dnsmasq.conf_), or merge it into the main hosts file by some other mechanism.

If your _dnsmasq_ server is a router with external storage attached it makes
sense to keep the hosts file the updater generates there, to minimize writes to
the router's onboard storage.

As an example, if you're using AsusWRT-Merlin/Entware, you can easily configure
the router to include this external file by writing to _/opt/etc/hosts_ and
adding the following to _/jffs/scripts/hosts.postconf_:

```sh
# for remote hosts updates
if [ -f /opt/etc/hosts ]; then
  cat "/opt/etc/hosts" >> "$CONFIG"
fi
```

As _dnsmasq_ may start before _/opt_ is mounted, _dnsmasq_ should be restarted in
_/jffs/scripts/post-mount_, to ensure container name resolution functions after
a router reboot:

```sh
if [ -d "$1/entware" ] ; then
  ln -nsf $1/entware /tmp/opt

  service restart_dnsmasq
fi
```

Relevant configuration parameters for Docker Dnsmasq Updater in this scenario
would be `--remote_file /opt/etc/hosts --remote_cmd 'service restart_dnsmasq'`.

If you're using a key instead of a password you'll need to add the appropriate
public key to _~/.ssh/authorized_keys_ on the router (possibly via the router's
webUI rather than the shell).

### Setup for other Docker containers
To enable Docker Dnsmasq Updater for an individual container there are three
labels that can be set:

*   `dnsmasq.updater.enable` - set this to "true"
*   `dnsmasq.updater.host`   - set this to the hostname(s) you want to use
*   `dnsmasq.updater.ip`     - override the default IP setting (Agent only)

`dnsmasq.updater.host` can be a single hostname or a space-separated list.

The updater will also add `hostname` and any `extra_hosts` attributes set for a
container, so `dnsmasq.updater.host` isn't strictly necessary if hostnames are
set as you want them for a container elsewhere.

If you choose to monitor a user-defined Docker network then
`dnsmasq.updater.enable` isn't strictly necessary either. The updater assumes
any container connecting to the monitored network is a container that you want
working DNS for.

Leave `dnsmasq.updater.ip` unset to use the default.

Any defined `extra_hosts` will be given the IP from that definition.

### Use with Traefik
Docker Dnsmasq Updater will pull Traefik hostnames set on containers via the
``traefik.http.routers.<router>.rule=Host(`<hostname>`)`` label, including
multiple hostnames specified in the
``Host(`<hostname1>`) || Host(`<hostname2>`)`` form.

As all containers joining a monitored network are considered valid, if you
monitor a user-defined network that Traefik uses you don't need to set any
`dnsmasq.updater.*` labels at all, it gets what it needs from the network and
Traefik labels.

This scenario provides the easiest/laziest configuration route, with no specific
Docker Dnsmasq Updater configuration required on containers.

#### Redirecting 'www' subdomains
The `--prepend_www` functionality was added primarily for robustness. Sometimes
people add `www.` to URLs for no good reason, then don't know what to make of
the ensuing DNS lookup error messages in their browser.

To resolve this without having to add `www.*` hostnames to every container
manually, we can create the DNS records globally with `--prepend_www` and then
redirect to the _non-www_ domain in a reverse proxy.

In Traefik this can be done with a router and a middleware added to the dynamic
configuration:
```yaml
http:
  routers:
    redirect-www:
      # match any host starting with 'www.'
      rule: "HostRegexp(`{host:www.+}`)"
      # use a low priority to allow overrides on specific containers
      priority: 1
      entryPoints:
        - web
        - websecure
      middlewares: strip-www@file
      service: noop@internal

  middlewares:
    strip-www:
      redirectRegex:
        regex: "^(https?)://www\\.(.*)"
        replacement: "$1://$2"
        permanent: true
```

## Known Issues
#### pyinit_main: can't initialize time
The container may fail to start on some ARM devices with this error:

```
Fatal Python error: pyinit_main: can't initialize time
Python runtime state: core initialized
PermissionError: [Errno 1] Operation not permitted
```

This is caused by [a bug in libseccomp](https://github.com/moby/moby/issues/40734)
and can be resolved by either updating libseccomp on the Docker _host_ (to at
least 2.4.x) or running the container with `--security-opt seccomp=unconfined`
set in the `docker run` command.

On a Debian-based host (e.g. Armbian) it may be necessary to add the backports
repo for apt to find the newest version.

## Links
GitHub: <https://github.com/moonbuggy/docker-dnsmasq-updater>

Docker Hub: <https://hub.docker.com/r/moonbuggy2000/dnsmasq-updater>

### Resources
Pre-built Python musl wheels: <https://github.com/moonbuggy/docker-python-musl-wheels>

[AsusWRT-Merlin]: https://www.asuswrt-merlin.net/
[Entware]: https://entware.net/about.html
