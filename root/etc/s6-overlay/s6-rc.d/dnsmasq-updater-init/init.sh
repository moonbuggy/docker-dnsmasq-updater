#!/usr/bin/with-contenv /bin/sh
#shellcheck shell=sh

CONFIG_FILE="${APP_PATH:-/app}/conf/dnsmasq_updater.conf"

if env | grep -q 'DMU_'; then
	[ ! -z "${DMU_IP}" ] && sed "s!^ip.*!ip=${DMU_IP}!" -i $CONFIG_FILE

	[ ! -z "${DMU_DOMAIN}" ] \
		&& { sed "s!^domain.*!domain=${DMU_DOMAIN}!" -i $CONFIG_FILE; } \
		|| sed "s!^domain.*!domain=docker!" -i $CONFIG_FILE

	[ ! -z "${DMU_DOCKER_SOCKET}" ] && sed "s!^docker_socket.*!docker_socket=${DMU_DOCKER_SOCKET}!" -i $CONFIG_FILE
	[ ! -z "${DMU_NETWORK}" ] && sed "s!^network.*!network=${DMU_NETWORK}!" -i $CONFIG_FILE
	[ ! -z "${DMU_SERVER}" ] && sed "s!^server.*!server=${DMU_SERVER}!" -i $CONFIG_FILE

	[ ! -z "${DMU_PREPEND_WWW}" ] \
		&& sed -E "s!^#?prepend_www.*!prepend_www=${DMU_PREPEND_WWW}!" -i $CONFIG_FILE \
		|| sed -E "s!^#?prepend_www.*!prepend_www=False!" -i $CONFIG_FILE \

	[ ! -z "${DMU_PORT}" ] \
		&& { sed "s!^port.*!port=${DMU_PORT}!" -i $CONFIG_FILE; } \
		|| sed "s!^port.*!port=22!" -i $CONFIG_FILE

	[ ! -z "${DMU_LOGIN}" ] && sed "s!^login.*!login=${DMU_LOGIN}!" -i $CONFIG_FILE
	[ ! -z "${DMU_PASSWORD}" ] && sed "s!^password.*!password=${DMU_PASSWORD}!" -i $CONFIG_FILE
	[ ! -z "${DMU_KEY}" ] && sed "s!^key.*!key=${DMU_KEY}!" -i $CONFIG_FILE
	[ ! -z "${DMU_REMOTE_FILE}" ] && sed "s!^file.*!file=${DMU_REMOTE_FILE}!" -i $CONFIG_FILE

	[ ! -z "${DMU_REMOTE_CMD}" ] \
		&& { sed "s!^remote_cmd.*!remote_cmd=${DMU_REMOTE_CMD}!" -i $CONFIG_FILE; } \
		|| sed "s!^remote_cmd.*!remote_cmd=service restart_dnsmasq!" -i $CONFIG_FILE

	[ ! -z "${DMU_DELAY}" ] && sed "s!^delay.*!delay=${DMU_DELAY}!" -i $CONFIG_FILE

	sed "s!^ready_fd.*!ready_fd=5!" -i $CONFIG_FILE
fi
