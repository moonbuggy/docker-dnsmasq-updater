#! /bin/bash

#NOOP='true'
NOPUSH='true'
#NOBUILD='true'

DOCKER_REPO="${DOCKER_REPO:-moonbuggy2000/dnsmasq-updater}"
DOCKER_TAG="${1:-latest}"
IMAGE_NAME="${DOCKER_REPO}:${DOCKER_TAG}"

[ -n "${NOOP}" ] && printf '** NOOP set. Will not execute pushes.\n\n'

printf 'image name: %s\n\n' "${IMAGE_NAME}"

. hooks/post_checkout
. hooks/pre_build
. hooks/build
. hooks/push
. hooks/post_push
