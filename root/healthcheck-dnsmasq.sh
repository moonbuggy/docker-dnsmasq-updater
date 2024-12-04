#!/usr/bin/with-contenv /bin/sh
#shellcheck shell=sh

up_up="$(s6-svstat -o up /var/run/service/dnsmasq-updater/)"
up_ready="$(s6-svstat -o ready /var/run/service/dnsmasq-updater/)"

dnsmasq_up="$(s6-svstat -o up /var/run/service/dnsmasq/)"

nslookup dnsmasq.00test00 127.0.0.1 >/dev/null 2>&1 \
	&& dnsmasq_ready="true" \
	|| dnsmasq_ready="false"

echo "Dnsmasq Updater - Up: ${up_up}, Ready: ${up_ready}"
echo "DNS Sever - Up: ${dnsmasq_up}, Ready: ${dnsmasq_ready}"

[ "x${up_up}" = "xtrue" ] && [ "x${up_ready}" = "xtrue" ] \
	&& [ "x${dnsmasq_up}" = "xtrue" ] && [ "x${dnsmasq_ready}" = "xtrue" ] \
	&& exit 0

exit 1
