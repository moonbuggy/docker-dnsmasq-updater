#! /bin/bash

#NOOP='true'
#DO_PUSH='true'
#NO_BUILD='true'

DOCKER_REPO="${DOCKER_REPO:-moonbuggy2000/dnsmasq-updater}"

all_tags='alpine alpine-binary'
default_tag='alpine'

. "hooks/.build.sh"
