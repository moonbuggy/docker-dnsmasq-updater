#! /bin/sh

cd "${APP_PATH}" || exit

PUID="${PUID:-1000}"
GUID="${GUID:-1000}"

# create user and group for sshd test and to own the output files
addgroup -g "${GUID}" ssh_test
adduser -D -u "${PUID}" -G ssh_test -s /bin/ash ssh_test
passwd -u ssh_test
echo "ssh_test:ssh_test" | chpasswd

# create and configure SSH key for connection
#ssh-keygen -t rsa -q -f "id_rsa" -N "ssh_test"
ssh-keygen -t rsa -q -f "id_rsa" -N ""
mkdir -p /home/ssh_test/.ssh
cp id_rsa.pub /home/ssh_test/.ssh/authorized_keys

# start sshd
/usr/sbin/sshd -e &

# dnsmasq-updater config
sed -i "${APP_PATH}/conf/dnsmasq_updater.conf" \
		-e 's|ip=.*|ip=192.168.1.1|' \
		-e 's|network=.*|network=traefik|' \
		-e 's|server=.*|server=localhost|' \
		-e 's|login=.*|login=ssh_test|' \
		-e 's|key=.*|key=/app/id_rsa|' \
		-e 's|password=.*|password=ssh_test|' \
		-e 's|remote_cmd=.*|remote_cmd=true|' \
		-e 's|file=.*|file=hosts|' \
		-e 's|ready_fd=.*|ready_fd=2|'

# get hints
python3 get-hints.py dnsmasq_updater --debug -c conf/dnsmasq_updater.conf

# move hints to mounted volume
filename_orig="$(ls *.json)"
filename_new="$(echo "${filename_orig}" | cut -d'.' -f1)-${TARGET_ARCH_TAG}-raw.json"
cp -f "${filename_orig}" "/output/${filename_new}"
chown -R "${PUID}":"${GUID}" "/output/${filename_new}"
