#!/usr/bin/with-contenv /bin/sh
#shellcheck shell=sh

dnsmasq_up="$(s6-svstat -o up /var/run/service/dnsmasq/)"

nslookup dnsmasq.00test00 127.0.0.1 >/dev/null 2>&1 \
	&& dnsmasq_ready="true" \
	|| dnsmasq_ready="false"

echo "DNS Sever - Up: ${dnsmasq_up}, Ready: ${dnsmasq_ready}"

[ "x${dnsmasq_up}" != "xtrue" ] || [ "x${dnsmasq_ready}" != "xtrue" ] \
	&& exit 1
