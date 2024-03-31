#!/usr/bin/with-contenv /bin/sh
#shellcheck shell=sh

CONFIG_FILE="${APP_PATH:-/app}/conf/dnsmasq_updater.conf"

if env | grep -q 'DMU_'; then
	[ ! -z "${DMU_MODE}" ] && sed "s!^mode.*!mode=${DMU_MODE}!" -i $CONFIG_FILE
	[ ! -z "${DMU_HOSTS_LOCATION}" ] && sed "s!^location.*!location=${DMU_HOSTS_LOCATION}!" -i $CONFIG_FILE

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

	# some variables have been renamed, default to the old names if the new name
	# is unset so we don't break existing containers
	DMU_HOSTS_FILE="${DMU_HOSTS_FILE:-${DMU_REMOTE_FILE}}"
	[ ! -z "${DMU_HOSTS_FILE}" ] && sed "s!^file.*!file=${DMU_HOSTS_FILE}!" -i $CONFIG_FILE

	DMU_RESTART_CMD="${DMU_RESTART_CMD:-${DMU_REMOTE_CMD}}"
	[ ! -z "${DMU_RESTART_CMD}" ] \
		&& { sed -E "s!^(restart_cmd|remote_cmd).*!restart_cmd=${DMU_RESTART_CMD}!" -i $CONFIG_FILE; } \
		|| sed -E "s!^(restart_cmd|remote_cmd).*!restart_cmd=service restart_dnsmasq!" -i $CONFIG_FILE

	[ ! -z "${DMU_DELAY}" ] && sed "s!^delay.*!delay=${DMU_DELAY}!" -i $CONFIG_FILE

	# configuration for the agent
	[ ! -z "${DMU_API_SERVER}" ] && sed "s!^api_server.*!api_server=${DMU_API_SERVER}!" -i $CONFIG_FILE
	[ ! -z "${DMU_API_PORT}" ] \
		&& { sed "s!^api_port.*!api_port=${DMU_API_PORT}!" -i $CONFIG_FILE; } \
		|| sed "s!^api_port.*!api_port=8080!" -i $CONFIG_FILE
	[ ! -z "${DMU_API_KEY}" ] && sed "s!^api_key.*!api_key=${DMU_API_KEY}!" -i $CONFIG_FILE
	[ ! -z "${DMU_API_RETRY}" ] && sed "s!^api_retry.*!api_retry=${DMU_API_RETRY}!" -i $CONFIG_FILE

	sed "s!^ready_fd.*!ready_fd=5!" -i $CONFIG_FILE
fi
