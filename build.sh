#! /bin/bash
# shellcheck disable=SC2034

#NOOP='true'
#DO_PUSH='true'
#NO_BUILD='true'

DOCKER_REPO="${DOCKER_REPO:-moonbuggy2000/dnsmasq-updater}"

# all_tags='alpine alpine-binary agent agent-binary'
all_tags='alpine agent'
default_tag='alpine agent'

. "hooks/.build.sh"
