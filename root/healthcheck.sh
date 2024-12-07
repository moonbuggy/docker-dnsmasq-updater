#!/usr/bin/with-contenv /bin/sh
# shellcheck shell=sh

dmu_up="$(s6-svstat -o up /var/run/service/dnsmasq-updater/)"
dmu_ready="$(s6-svstat -o ready /var/run/service/dnsmasq-updater/)"

echo "Dnsmasq Updater - Up: ${dmu_up}, Ready: ${dmu_ready}"

[ ! -z "${DNSMASQ_SERVER_MODE+set}" ] \
	&& . /healthcheck-dnsmasq.sh

[ "x${dmu_up}" = "xtrue" ] && [ "x${dmu_ready}" = "xtrue" ] \
	&& exit 0

exit 1
