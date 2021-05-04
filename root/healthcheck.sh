#!/bin/sh

up="$(s6-svstat -o up /var/run/s6/services/dnsmasq-updater/)"
ready="$(s6-svstat -o ready /var/run/s6/services/dnsmasq-updater/)"

echo "Up: ${up}, Ready: ${ready}"

if [ "$up" == "true" ] && [ "$ready" == "true" ]; then
	exit 0
else
	exit 1
fi
