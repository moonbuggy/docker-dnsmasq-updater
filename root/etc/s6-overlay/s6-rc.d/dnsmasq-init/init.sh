#!/usr/bin/with-contenv /bin/sh
#shellcheck shell=sh

CONFIG_FILE="/etc/dnsmasq.conf"

cut_conf_lines () {
  grep -v "^${1}=" ${CONFIG_FILE} >dnsmasq.conf.tmp
  mv -f dnsmasq.conf.tmp ${CONFIG_FILE}
}

printf "nameserver ::1\nnameserver 127.0.0.1\n" > /etc/resolv.conf

DMU_DOMAIN="${DMU_DOMAIN:-docker}"
echo "dnsmasq-init: info: local domain: ${DMU_DOMAIN}"
cut_conf_lines local
sed -E "s|__LOCALS__$|__LOCALS__\nlocal=/00test00/\nlocal=/${DMU_DOMAIN}/|" -i ${CONFIG_FILE}

DMU_HOSTS_FILE="${DMU_HOSTS_FILE:-/etc/hosts.updater}"
echo "dnsmasq-init: info: hosts file: ${DMU_HOSTS_FILE}"
# sed -e "s|^addn-hosts=.*$|addn-hosts=${DMU_HOSTS_FILE}|" \
#   -i ${CONFIG_FILE}
touch /etc/hosts.test
cut_conf_lines addn-hosts
sed -e "s|__ADDN_HOSTS__$|__ADDN_HOSTS__\naddn-hosts=/etc/hosts.test\naddn-hosts=${DMU_HOSTS_FILE}|" \
  -i ${CONFIG_FILE}

touch ${DMU_HOSTS_FILE}

if env | grep -q 'DNS_'; then
  # resolve.conf doesn't like a servier being on a non-default port
  # [ ! -z "${DNS_PORT}" ] \
  #   && echo "dnsmasq-init: info: port: ${DNS_PORT}" \
  #   && sed "s|^port=.*$|port=${DNS_PORT}|" -i ${CONFIG_FILE}

  if [ ! -z "${DNS_SERVERS}" ]; then
    unset upstream_string

    # reversing the loop direction with tac means we end up with the 'server='
    # entries in the same order as they are in the ENV variable, which doesn't
    # make any difference to anything and is pointless
    for upstream_server in $(echo ${DNS_SERVERS} | tr ' ' '\n' | tac); do
      echo "dnsmasq-init: info: upstream server: ${upstream_server}"
      upstream_string="server=${upstream_server}\n${upstream_string}"
    done

    # busybox's sed won't handle multiline patterns so we have to use grep to
    # remove 'server=.*' strings including the newline at the end - otherwise
    # we end up adding newlines to the config file every time we init
    # grep -v '^server=' ${CONFIG_FILE} >dnsmasq.conf.tmp
    # mv -f dnsmasq.conf.tmp ${CONFIG_FILE}
    cut_conf_lines server
    sed "s|__SERVERS__$|__SERVERS__\n${upstream_string%??}|" \
      -i ${CONFIG_FILE}
  fi

  printf "dnsmasq-init: info: log-queries: "
  if [ ! -z "${DNS_LOG_QUERIES}" ]; then
    echo "true"
    sed -E "s|^#?log-queries.*$|log-queries|" -i ${CONFIG_FILE}
  else
    echo "false"
    sed "s|^log-queries.*$|#log-queries|" -i ${CONFIG_FILE}
  fi
fi

if [ ! -z ${DNS_DEBUG+set} ] || [ ! -z ${DEBUG+set} ]; then
  echo "===== ${CONFIG_FILE} ====="
  cat "${CONFIG_FILE}"
  echo "===== INIT END ====="
fi
