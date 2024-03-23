# Docker Dnsmasq Updater
Automatically update a remote hosts file with Docker container hostnames.

*   [Rationale](#rationale)
*   [What It Does](#what-it-does)
*   [Usage](#usage)
*   [Setup](#setup)
    *   [Installation on Docker host](#installation-on-docker-host)
    *   [Installation in Docker container](#installation-in-docker-container)
    *   [Setup on dnsmasq server](#setup-on-dnsmasq-server)
    *   [Setup for other Docker containers](#setup-for-other-docker-containers)
    *   [Use with Traefik](#use-with-traefik)
*   [Known Issues](#known-issues)
*   [Links](#links)

## Rationale
If you have a LAN with your router using dnsmasq for local DNS you may find
yourself frequently updating a hosts file as you add or remove Docker
containers. The currently available options for automating this typically
require you to put Docker containers in a subdomain (e.g. \*.docker.local)
and/or, if you want to keep the containers in the top level domain (e.g.
\*.local), installing a full-fledged name server on the router and syncing it
with the same in a container on the Docker host.

Docker Dnsmasq Updater allows host names to be added or removed automatically
without added complexity or resource demands on the router. It can be run as a
standalone script on the Docker host or in a container, it only needs access to
the Docker socket and SSH access to the router (or any device providing local
DNS with a hosts file).

This script has been built with an [AsusWRT-Merlin][]/[Entware][] router in
mind, but should work with any device running dnsmasq or using a hosts file.

## What It Does
-   Runs on the Docker host OR in a container
-   On load, scans all running containers for a `dnsmasq.updater.enable` label
-   Optionally, on load, scans a specified Docker network for running containers
-   After loading, monitors the Docker socket for containers starting/stopping
    and optionally connecting/disconnecting to a specified Docker network
-   Finds any hostnames for containers meeting criteria
-   Writes a remote hosts file
-   Restarts a remote dnsmasq server

Currently the updater is built for a standalone Docker host, generally only
working with a single host IP (with the exception of `extra_hosts`).

## Usage
```
usage: dnsmasq_updater.py [-h] [-c FILE] [--debug] [-i IP] [-d DOMAIN] [-w]
                          [-D SOCKET] [-n NETWORK] [-s SERVER] [-P PORT] [-l USERNAME]
                          [-k FILE] [-p PASSWORD] [-f FILE] [-r COMMAND] [-t SECONDS]
                          [--ready_fd INT]

Docker Dnsmasq Updater

optional arguments:
  -h, --help            show this help message and exit
  -c FILE, --config_file FILE
                        external configuration file
  --debug               turn on debug messaging
  -i IP, --ip IP        IP for the DNS record
  -d DOMAIN, --domain DOMAIN
                        domain/zone for the DNS record (default: 'docker')
  -w, --prepend_www     add 'www' subdomains for all hostnames
  -D SOCKET, --docker_socket SOCKET
                        path to the docker socket (default: 'unix://var/run/docker.sock')
  -n NETWORK, --network NETWORK
                        Docker network to monitor
  -s SERVER, --server SERVER
                        dnsmasq server address
  -P PORT, --port PORT  port for SSH on the dnsmasq server (default: '22')
  -l USERNAME, --login USERNAME
                        login name for the dnsmasq server
  -k FILE, --key FILE   identity/key file for SSH to the dnsmasq server
  -p PASSWORD, --password PASSWORD
                        password for the dnsmasq server OR for an encrypted SSH key
  -f FILE, --file FILE  the file (including path) to write on the dnsmasq server
  -r COMMAND, --remote_cmd COMMAND
                        the update command to execute on the dnsmasq server
  -t SECONDS, --delay SECONDS
                        delay for writes to the dnsmasq server (default: '10')
  --ready_fd INT        set to an integer to enable signalling readiness by writing
                        a new line to that integer file descriptor
```

Any command line parameters take precedence over settings in
`dnsmasq_updater.conf`.

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

## Setup
Docker Dnsmasq Updater requires at least Python 3.6 and the docker, paramiko and
python_hosts modules.

The script can be run standalone on the Docker host or in a Docker container, so
long as it has access to the Docker socket it's happy.

You do not need to both install it on the host and run the container, it would
in fact be a bad idea to do so. Choose one or the other, whichever you feel
works best for you.

### Installation on Docker host
Install requirements: `pip3 install -r requirements.txt`

Put `dnsmasq_updater.py` anywhere in the path.

Put `dnsmasq_updater.conf` in `/etc/` or in the same directory as the script
(which takes precedence over any config file in `/etc/`).

### Installation in Docker container
```sh
docker run -d \
  --name dnsmasq-updater \
  -v /var/run/docker.sock:/var/run/docker.sock \
  moonbuggy2000/dnsmasq-updater
```

If you're using a config file instead of environment variables (see below)
you'll need to persist it with `-v <host path>:/app/conf/dnsmasq_updater.conf`.
If you're using an SSH key for authentication you can persist and use the
`/app/keys/` folder.

#### Tags
To minimize the Docker image size, and to theoretically improve run times (I
haven't benchmarked it because I believe it runs fast enough either way) a
binary build is available, tagged as `binary`.

A build using the un-compiled Python script is available, tagged `script`.

The default `latest` tag points to the script version.

> [!NOTE]
> After upgrading the Nuitka version, binary builds are currently larger than
> the the un-compiled images. I'm not sure it's worth the time and effort to
> investigate what's changed. I may stop building the binary images.
>
> The 'latest' tag now points to the script instead of the binary, since it's
> become the better option.

Tags may be prefixed with `<version>-` to get a specific version, or just use a
version number by itself to get `<version>-script`.

#### Architectures
The main `latest`, `<version>`, `binary` and `script` tags should automatically
provide images compatible with `amd64`, `arm`/`armv7`, `armhf`/`armv6`, `arm64`,
`386` and `ppc64le` platforms. Tags for specific single-arch images are
available, in the form `alpine-<arch>` and `alpine-binary-<arch>` for the
`script` and `binary` builds respectively.

**Note:** I'm only able to test on `amd64` and `armv7`. Both `script` and
`binary` builds currently work on these architectures. The `script` build is
more portable and less likely to have problems on un-tested architectures
(although the `binary` builds _should_ be fine as well). If `binary` doesn't
work on a particular piece of hardware, `script` would be worth trying.

#### Docker environment variables
Almost all the command line parameters (see [Usage](#usage)) can be set with
environment variables:

*   `DMU_IP`          - IP for the DNS records
*   `DMU_DOMAIN`      - domain/zone for the DNS records, defaults to `docker`
*   `DMU_PREPEND_WWW` - add `www` subdomains to all hostnames, defaults to `False`
*   `DMU_NETWORK`     - Docker network to monitor, defaults to none/disabled
*   `DMU_SERVER`      - dnsmasq server address
*   `DMU_PORT`        - dnsmasq server SSH port, defaults to `22`
*   `DMU_LOGIN`       - dnsmasq server login name
*   `DMU_PASSWORD`    - password for the login name or, if a key is specified, decryption of the key
*   `DMU_KEY`         - full path to SSH key file
*   `DMU_REMOTE_FILE` - full path to the hosts file to update on the dnsmasq server
*   `DMU_REMOTE_CMD`  - remote command to execute to restart/update dnsmasq,defaults to `service restart_dnsmasq`
*   `DMU_DELAY`       - delay in seconds before writing remote hosts file, defaults to `10`
*   `DMU_DEBUG`       - set `True` to enable debug log output
*   `TZ`		          - set timezone

### Setup on dnsmasq server
Docker Dnsmasq Updater won't track changes other software (i.e dnsmasq) might
make to the remote hosts file. Thus, to avoid conflicts, it's best to give
Docker Dnsmasq Updater it's own hosts file to use and either specify it as an
additional hosts file to dnsmasq (with the `-addn-hosts <file>` argument, or in
`dnsmasq.conf`), or merge it into the main hosts file by some other mechanism.

If your dnsmasq server is a router with external storage attached it makes sense
to keep the hosts file the updater generates there, to minimize writes to the
router's onboard storage.

As an example, if you're using AsusWRT-Merlin/Entware, you can easily configure
the router to include this external file by writing to `/opt/etc/hosts` and
adding the following to `/jffs/scripts/hosts.postconf`:

```sh
# for remote hosts updates
if [ -f /opt/etc/hosts ]; then
  cat "/opt/etc/hosts" >> "$CONFIG"
fi
```

As dnsmasq may start before `/opt` is mounted, dnsmasq should be restarted in
`/jffs/scripts/post-mount`, to ensure container name resolution functions after
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
public key to `~/.ssh/authorized_keys` on the router (possibly via the router's
webUI rather than the shell).

### Setup for other Docker containers
To enable Docker Dnsmasq Updater for an individual container there are two
labels that can be set:

*   `dnsmasq.updater.enable` - set this to "true"
*   `dnsmasq.updater.host`   - set this to the hostname(s) you want to use

`dnsmasq.updater.host` can be a single hostname or a space-separated list.

The updater will also add `hostname` and any `extra_hosts` attributes set for a
container, so `dnsmasq.updater.host` isn't strictly necessary if hostnames are
set as you want them for a container elsewhere.

If you choose to monitor a user-defined Docker network then
`dnsmasq.updater.enable` isn't strictly necessary either. The updater assumes
any container connecting to the monitored network is a container that you want
working DNS for.

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
The `--prepend_www` funtionality was added primarily for robustness. Sometimes
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

This is caused by
[a bug in libseccomp](https://github.com/moby/moby/issues/40734) and can be
resolved by either updating libseccomp on the Docker _host_ (to at least 2.4.x)
or running the container with `--security-opt seccomp=unconfined` set in the
`docker run` command.

On a Debian-based host (e.g. Armbian) it may be necessary to add the backports
repo for apt to find the newest version.

## Links
GitHub: <https://github.com/moonbuggy/docker-dnsmasq-updater>

Docker Hub: <https://hub.docker.com/r/moonbuggy2000/dnsmasq-updater>

### Resources
Pre-built Python musl wheels: <https://github.com/moonbuggy/docker-python-musl-wheels>


[AsusWRT-Merlin]: https://www.asuswrt-merlin.net/
[Entware]: https://entware.net/about.html
