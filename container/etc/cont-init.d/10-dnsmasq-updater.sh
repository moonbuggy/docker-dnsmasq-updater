#!/usr/bin/with-contenv /bin/sh

CONFIG_FILE=${APP_PATH}/conf/dnsmasq_updater.conf

if $(env | grep -q DMU_); then

	if [ ! -z ${DMU_IP} ]; then
		sed -i "s!^ip.*!ip=${DMU_IP}!" $CONFIG_FILE
	fi
	if [ ! -z ${DMU_DOMAIN} ]; then
		sed -i "s!^domain.*!domain=${DMU_DOMAIN}!" $CONFIG_FILE
	else
		sed -i "s!^domain.*!domain=docker!" $CONFIG_FILE
	fi
    if [ ! -z ${DMU_DOCKER_SOCKET} ]; then
        sed -i "s!^docker_socket.*!docker_socket=${DMU_DOCKER_SOCKET}!" $CONFIG_FILE
    fi
	if [ ! -z ${DMU_NETWORK} ]; then
		sed -i "s!^network.*!network=${DMU_NETWORK}!" $CONFIG_FILE
	fi
	if [ ! -z ${DMU_SERVER} ]; then
		sed -i "s!^server.*!server=${DMU_SERVER}!" $CONFIG_FILE
	fi
	if [ ! -z ${DMU_PORT} ]; then
		sed -i "s!^port.*!port=${DMU_PORT}!" $CONFIG_FILE
	else
		sed -i "s!^port.*!port=22!" $CONFIG_FILE
	fi
	if [ ! -z ${DMU_LOGIN} ]; then
		sed -i "s!^login.*!login=${DMU_LOGIN}!" $CONFIG_FILE
	fi
	if [ ! -z ${DMU_PASSWORD} ]; then
		sed -i "s!^password.*!password=${DMU_PASSWORD}!" $CONFIG_FILE
	fi
	if [ ! -z ${DMU_KEY} ]; then
		sed -i "s!^key.*!key=${DMU_KEY}!" $CONFIG_FILE
	fi
	if [ ! -z ${DMU_REMOTE_FILE} ]; then
		sed -i "s!^file.*!file=${DMU_REMOTE_FILE}!" $CONFIG_FILE
	fi
	if [ ! -z ${DMU_REMOTE_CMD} ]; then
		sed -i "s!^remote_cmd.*!remote_cmd=${DMU_REMOTE_CMD}!" $CONFIG_FILE
	else
		sed -i "s!^remote_cmd.*!remote_cmd=service restart_dnsmasq!" $CONFIG_FILE
	fi

	sed -i "s!^ready_fd.*!ready_fd=5!" $CONFIG_FILE
fi

