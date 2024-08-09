#!/usr/bin/with-contenv /bin/sh
# shellcheck shell=sh

up="$(s6-svstat -o up /var/run/service/dnsmasq-updater/)"

# although we still signal the file descriptor in --manager mode, just like in
# --standalone mode, it makes more sense to indicate "ready" based on a response
# from the API
ready="$(wget -qO- http://127.0.0.1:${DMU_API_PORT:-8080}/status >/dev/null 2>&1 \
				&& echo 'true' || echo 'false')"

echo "Up: ${up}, Ready: ${ready}"

[ "x${up}" = "xtrue" ] && [ "x${ready}" = "xtrue" ] \
	&& exit 0

exit 1
