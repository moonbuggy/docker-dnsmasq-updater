#! /bin/bash
# shellcheck disable=SC2034

DOCKER_REPO="${DOCKER_REPO:-moonbuggy2000/dnsmasq-updater}"

# all_tags='alpine alpine-binary agent agent-binary'
all_tags='alpine agent server'
default_tag='alpine agent server'

. "hooks/.build.sh"
