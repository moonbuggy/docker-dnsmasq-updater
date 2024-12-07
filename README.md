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
        *   [Image Tags](#image-tags)
        *   [Standalone deployment](#standalone-deployment)
        *   [Standalone DNS Server deployment](#standalone-dns-server-deployment)
        *   [Swarm deployment](#swarm-deployment)
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
                          [--standalone | --manager] [-D SOCKET] [-n NETWORK][-i IP]
                          [-d DOMAIN] [-L PROXIES] [-w] [--remote | --local]
                          [-f FILE] [-r COMMAND] [-t SECONDS] [-s SERVER] [-P PORT]
                          [-l USERNAME] []-k FILE] [-p PASSWORD] [--api_address IP]
                          [--api_port PORT] [--api_key KEY] [--api_backend STRING]

Docker Dnsmasq Updater

options:
  -h, --help            show this help message and exit
  -c FILE, --config_file FILE
                        external configuration file
  --debug               turn on debug messaging
  --ready_fd INT        set to an integer to enable signalling readiness by
                        writing a new line to that integer file descriptor

Mode:
  --standalone          running on a standalone Docker host (default)
  --manager             bring up the API and run as the manager for multiple
                        Docker nodes

Docker:
  -D SOCKET, --docker_socket SOCKET
                        path to the docker socket
                        (default: 'unix://var/run/docker.sock')
  -n NETWORK, --network NETWORK
                        Docker network to monitor

DNS:
  -i IP, --ip IP        default IP for the DNS records
  -d DOMAIN, --domain DOMAIN
                        domain/zone for the DNS record (default: 'docker')
  -L PROXIES, --labels_from PROXIES
                        add hostnames from labels set by other services
                        (standalone only, default: '')
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
                        password for the dnsmasq server OR for an encrypted SSH
                        key

API server (needed by --manager):
  --api_address IP      address for API to listen on (default: '0.0.0.0')
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
                                [-L PROXIES] [-s SERVER] [-P PORT] [-k KEY]
                                [-R SECONDS] [-t SECONDS]
                                [--clean_on_exit | --no-clean_on_exit]
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
                        path to the docker socket
                        (default: 'unix://var/run/docker.sock')
  -n NETWORK, --network NETWORK
                        Docker network to monitor

DNS:
  -L PROXIES, --labels_from PROXIES
                        add hostnames from labels set by other services
                        (default: '')

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
                        delay between checking the API server status
                        (default: '60')
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
(which takes precedence over any config file in `/etc/`). Otherwise, put it
anywhere and specify the location with `--config_file`.

### Installation of Docker container(s)
#### Image Tags

| image | tags |
| :--- | :--- |
| standalone/manager | script, latest, \<version\>, \<version\>-script |
| agent | agent, \<version\>-agent |
| standalone/manager with dnsmasq | server, \<version\>-server |

The default `latest` tag and the `script` tag point to the standalone/manager
script. Agent images will be tagged `agent`.

The `server` tag provides the standalone/manager script with _dnsmasq_
installed and configured in the container, ready to serve DNS requests for
Docker hostnames directly.

Tags may be prefixed with `<version>-` to get a specific version, or just use a
version number by itself to get `<version>-script`.

> [!NOTE]
> After upgrading the Nuitka version, binary builds are currently larger than the
> un-compiled images. There's also an issue building gunicorn (which is used as
> the API backend in the manager image) that I've not bothered investigating.
>
> As a result, for the time being at least, I've discontinued the `binary` builds.
> The build system remains capable of building them, and I may begin doing so
> again at some point. But not today.

##### Architectures
The main `latest`, `<version>`, `script`, `agent`, and `server` tags should
automatically provide images compatible with `amd64`, `arm`/`armv7`,
`armhf`/`armv6`, `arm64`, `386`,`ppc64le` and `s390x` platforms. Tags for
specific single-architecture images are no longer being pushed to Docker Hub.

> [!NOTE]
> I'm only able to test on `amd64`, `armv7` and `arm64`. The images currently
> work on these architectures. I assume they work on other architectures as
> well, but can't guarantee it..

#### Standalone deployment
```sh
docker run -d \
  --name dnsmasq-updater \
  -v /var/run/docker.sock:/var/run/docker.sock \
  moonbuggy2000/dnsmasq-updater
```

If you're using a config file instead of environment variables (see
[below](#docker-dnsmasq-updater-environment)) you'll need to persist it with `-v
<host path>:/app/conf/dnsmasq_updater.conf`. If you're using an SSH key for
authentication you can persist and use the _/app/keys/_ folder.

#### Standalone DNS Server deployment
Images tagged with `server` have _dnsmasq_ installed and Docker Dnsmasq
Updater configured to update it. These provide a working DNS server out of the
box, populated with hostnames of Docker containers that match the Updater's
configured criteria.

The `server` images contain the standalone/manager version of Docker Dnsmasq
Updater and inherit its configuration options, with some
[additional options](#docker-dnsmasq-updater-dns-server-environment)
for _dnsmasq_. A minimal configuration looks like this:
```yaml
version: '3.7'

services:
  dmu-server:
    image: moonbuggy2000/dnsmasq-updater:server
    hostname: dmu-dns-server
    environment:
      - DMU_DOMAIN=docker  # optional, this is the default
      - DMU_IP=<frontend_IP>
      - DMU_NETWORK=traefik  # optional
      - DMU_LABELS_FROM=traefik  # optional
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    ports:
      - 53:53/tcp
      - 53:53/udp
    networks:  # optional
      - traefik

networks:  # optional
  traefik:
    external: true
```
This compose file assumes there's a pre-existing Traefik network, but any
network can be used. If using container labels to select which containers get
hostnames updated, `DMU_NETWORK` and the network configuration can be omitted
entirely.

To customize _dnsmasq's_ configuration, persist and use _/etc/dnsmasq.d/_ for
extra _*.conf_ files. Don't edit _/etc/dnsmasq.conf_ directly, the init system
writes to it during startup, so changes may be overwritten.

#### Swarm deployment
##### docker-compose.yml
```yaml
version: '3.7'

services:
  dnsmasq-updater:
    image: moonbuggy2000/dnsmasq-updater:script
    hostname: dmu
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          # use a label to choose a specific Swarm node for the manager
          # this ensures the volume for /app/keys will be present
          - node.labels.dnsmasq-updater.manager == true
    environment:
      - DMU_DEBUG=false
      - DMU_MODE=manager
      - DMU_DOMAIN=swarm
      - DMU_IP=<frontend_IP>
      - DMU_KEY=/app/keys/id_rsa
      - DMU_LOGIN=<login>
      - DMU_PREPEND_WWW=true  # optional
      - DMU_HOSTS_FILE=/opt/etc/hosts.swarm
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
      - DMU_DEBUG=false  # optional
      - DMU_NETWORK=traefik  # optional
      - DMU_API_SERVER=dmu
      - DMU_API_PORT=8080
      - DMU_API_KEY=<api_key>
      - DMU_LABELS_FROM=traefik  # optional
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
      - traefik

  # test a single indirectly exposed container behind a traefik frontend
  whoami-frontend:
    image: traefik/whoami:latest
    hostname: whoami-frontend
    deploy:
      mode: replicated
      replicas: 1
      labels:
        - traefik.enable=true
        - traefik.http.routers.whoami-frontend.rule=Host(`whoami-frontend.swarm`)
        - traefik.http.routers.whoami-frontend.entryPoints=http,https
        - traefik.http.services.whoami-frontend.loadbalancer.server.port=80
    labels:
      - dnsmasq.updater.enable=true # can be omitted, we're on DMU_NETWORK
      - dnsmasq.updater.host=whoami-frontend.swarm # can be omitted, set by 'hostname' and traefik
      - dnsmasq.updater.ip=<frontend_IP> # can be omitted, it's the DMU_IP default
    networks:
      - traefik

  # assuming nothing at the dnsmasq end precludes it, test round-robin DNS for
  # a globally deployed and directly exposed service
  whoami-global:
    image: traefik/whoami:latest
    hostname: whoami-global
    deploy:
      mode: global
    ports:
      - 8888:80
    labels:
      - dnsmasq.updater.enable=true
      - dnsmasq.updater.host=whoami-global.swarm # can be omitted, set by 'hostname'
      - dnsmasq.updater.ip=host # override the default with node's IP

volumes:
  dnsmasq-updater_keys:
    name: dnsmasq-updater_keys

networks:
  traefik:
    external: true
```
This compose file assumes there's a pre-existing Traefik service and network,
but only the _whoami-frontend_ test service has Traefik-specific configuration.
This service should be modified as necessary if testing behind other frontends.

Docker Dnsmasq Updater itself isn't dependant on Traefik (or any particular
frontend) to run, but it's assumed there will be an ingress controller of some
sort in a Swarm environment, to route traffic on the default IP to indirectly
exposed services on individual nodes.

Since, in this case, the Agents are all connecting to the _traefik_ network
to monitor it for activity, it's convenient to stick the manager on this network
as well and use it for API communication.

The manager's `DMU_IP` default IP should point to a frontend/reverse proxy,
Traefik or otherwise. It's possible to override the default IP on a per-service
basis with with a `dnsmasq.updater.ip` label on individual services.

To meet the manager's constraints, the `dnsmasq-updater.manager` label will need
to be applied to the chosen node:
<code>docker node update --label-add dnsmasq-updater.manager=true \<node\></code>

See below for a detailed description of available
[environment variables](#docker-environment-variables).

The Agent should be allowed to restart freely since, by design, it will exit
upon encountering a variety of otherwise non-fatal errors. This is a simple way
to trigger a fresh initialisation and ensure the manager has the full picture if
it's restarted or communications are interrupted for whatever reason.

#### Docker environment variables
Almost all the command line parameters (see [Usage](#usage)) can be set with
environment variables.

##### Docker Dnsmasq Updater environment
*   `DMU_MODE`           - operation mode (accepts: _standalone_, _manager_; default: _standalone_)
*   `DMU_HOSTS_LOCATION` - location of hosts file (accepts: _local_, _remote_; default: _remote_)
*   `DMU_IP`             - default IP for the DNS records
*   `DMU_DOMAIN`         - domain/zone for the DNS records (default: _docker_)
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
*   `DMU_LABELS_FROM`    - add hostnames from labels set by other services (standalone only, accepts: _traefik_, _none_; default: _traefik_)
*   `DMU_PREPEND_WWW`    - add _www_ subdomains to all hostnames (default: _False_)
*   `DMU_DEBUG`          - set _True_ to enable debug log output
*   `TZ`		             - set timezone

##### Docker Dnsmasq Updater Agent environment
*   `DMU_DOCKER_SOCKET`  - path to the docker socket (default: _unix://var/run/docker.sock_)
*   `DMU_NETWORK`        - Docker network to monitor (default: none/disabled)
*   `DMU_API_SERVER`     - API server address
*   `DMU_API_PORT`       - port the API is listening on (default: _8080_)
*   `DMU_API_KEY`        - API access key
*   `DMU_API_RETRY`      - delay (in seconds) before retrying failed connection (default: _10_)
*   `DMU_API_CHECK`      - delay (in seconds) between checking the API server status (default: _60_)
*   `DMU_CLEAN_ON_EXIT`  - delete this device's hosts from the API when the Agent shuts down (default: _True_)
*   `DMU_LABELS_FROM`    - add hostnames from labels set by other services (accepts: _traefik_, _none_; default: _traefik_)
*   `DMU_DEBUG`          - set _True_ to enable debug log output
*   `TZ`		             - set timezone

##### Docker Dnsmasq Updater DNS Server environment
As well as inheriting the environment variables from the Standalone/Manager image
(see above), there's some extra for _dnsmasq_:
*   `DNS_SERVERS`        - a space separated list of upstream DNS servers (default: _1.1.1.1 8.8.8.8_)
*   `DNS_LOG_QUERIES`    - set _True_ to enable DNS query log output
*   `DNS_DEBUG`          - set _True_ to enable _dnsmasq_ debug log output

Some environment variables are pre-configured in the DNS Server image and
shouldn't be set or changed: `DMU_HOSTS_LOCATION`, `DMU_HOSTS_FILE`,
`DMU_RESTART_CMD`

The `TZ` parameter is only used to set timestamps on log messages.

### Setup on dnsmasq server
Docker Dnsmasq Updater won't track changes other software (i.e _dnsmasq_) might
make to the hosts file. Thus, to avoid conflicts, it's best to give Docker
Dnsmasq Updater it's own hosts file to use and either specify it as an
additional hosts file to _dnsmasq_ (with the `-addn-hosts <file>` argument, or
in _dnsmasq.conf_), or merge it into the main hosts file by some other mechanism.

If your _dnsmasq_ server is a router with external storage attached it makes
sense to keep the hosts file the updater generates there, to minimize writes to
the router's onboard storage.

If you're using a key instead of a password you'll need to add the appropriate
public key to _~/.ssh/authorized_keys_ on the router (possibly via the router's
webUI rather than the shell).

#### AsusWRT-Merlin/Entware example
As an example, if you're using AsusWRT-Merlin/Entware, you can easily configure
the router to include this external file by writing to _/opt/etc/hosts.docker_
and adding the following to _/jffs/scripts/hosts.postconf_:

```sh
# for remote hosts updates
if [ -f /opt/etc/hosts.docker ]; then
  cat "/opt/etc/hosts.docker" >> "$CONFIG"
fi
```

This will add the host definitions in _hosts.docker_ to _/etc/hosts_, which is
convenient if we want all host definitions in a single file for easy reference.

Alternatively, the `addn-hosts` method can be implemented through
_/jffs/configs/dnsmasq.conf.add_:

```sh
addn-hosts=/opt/etc/hosts.docker
```

This will result in _dnsmasq_ reading the _hosts.docker_ file directly.

In either case, as _dnsmasq_ may start before _/opt_ is mounted, _dnsmasq_
should be restarted in _/jffs/scripts/post-mount_, to ensure container name
resolution functions after a router reboot:

```sh
if [ -d "$1/entware" ] ; then
  ln -nsf $1/entware /tmp/opt
  service restart_dnsmasq
fi
```

Relevant configuration parameters for Docker Dnsmasq Updater in this scenario
would be `--remote_file /opt/etc/hosts.docker --restart_cmd 'service restart_dnsmasq'`.

#### Restart command
If _pkill_ is available on the _dnsmasq_ server, it may be better to send a
SIGHUP to trigger _dnsamsq_ to clear the cache and re-read the hosts file(s)
without restarting. In this scenario the default restart command would be
overridden with `--restart_cmd 'pkill -HUP dnsmasq'`.

However, if you're incorporating the _hosts.docker_ file through an init system
(as in the _hosts.postconf_ method in the example above), sending a SIGHUP to
_dnsmasq_ will bypass that init system and thus won't incorporate changes in the
file. A restart through the init system (i.e.
`--restart_cmd 'service restart_dnsmasq`) is required in this case.

A SIGHUP would be viable if using `addn-hosts` to let _dnsmasq_ read the file
directly.

### Setup for other Docker containers
To configure Docker Dnsmasq Updater for an individual container there are three
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

`dnsmasq.updater.ip` can be an IP address or the string `host`. Setting this to
`host` allows for directly exposed containers, using the Swarm node's IP address
(based on the device's hostname, as seen in the output from `docker info` under
`Name`, which must must be resolvable). Leave `dnsmasq.updater.ip` unset to use
the manager's default IP.

Any defined `extra_hosts` will be given the IP from that definition.

### Use with Traefik
If `DMU_LABELS_FROM=traefik` is set, Docker Dnsmasq Updater will pull Traefik
hostnames set on containers via the ``traefik.http.routers.<router>.rule=Host(`<hostname>`)``
label, including multiple hostnames specified in the
``Host(`<hostname1>`) || Host(`<hostname2>`)`` form.

For the time being, this is enabled by default in images (but not in the script).
At some future point this will be disabled by default in both cases.

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
