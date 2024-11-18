#! /bin/bash
# shellcheck shell=bash disable=SC2153

unset IMAGES_NOT_FOUND

log_debug () { [ ! -z "${DEBUG}" ] && >&2 printf "$*\n"; }

VERSION_REGEX="${VERSION_REGEX:-(^[0-9]*\.[\.0-9]*)}"

## stuff we'll need if we're going to figure out automatic updates
#
set_repo_data () {
  eval_param_ifn REPO_TAGS "docker_api_repo_tags ${DOCKER_REPO}"
  # if this is a new image there won't be any repo tags to pull.
  if [ ! -z "${REPO_TAGS}" ]; then
    ifFunc 'custom_target_versions' \
      && eval_param_ifn 'TARGET_REPO_VERSIONS' "custom_target_versions ${DOCKER_TAGS}" \
      || eval_param_ifn 'TARGET_REPO_VERSIONS' "echo ${REPO_TAGS} | xargs -n1 | grep -Eo \"${VERSION_REGEX//\\/\\\\}\" | sort -uV | xargs"
    eval_param_ifn 'TARGET_MAJOR_VERSIONS' "parse_version_major ${TARGET_REPO_VERSIONS}"
    eval_param_ifn 'TARGET_MINOR_VERSIONS' "parse_version_minor ${TARGET_REPO_VERSIONS}"
  else
     echo "Target repo doesn't appear to exist."
  fi

  eval_param_ifn 'SOURCE_REPO_TAGS' "docker_api_repo_tags ${SOURCE_REPO}"
  ifFunc 'custom_source_versions' \
    && eval_param_ifn 'SOURCE_REPO_VERSIONS' "custom_source_versions ${SOURCE_REPO_TAGS}" \
    || eval_param_ifn 'SOURCE_REPO_VERSIONS' "echo ${SOURCE_REPO_TAGS} | xargs -n1 | grep -Eo \"${VERSION_REGEX//\\/\\\\}\" | sort -uV | xargs"

  ifFunc 'custom_source_major_versions' \
    && eval_param_ifn 'SOURCE_MAJOR_VERSIONS' "custom_source_major_versions ${SOURCE_REPO_VERSIONS}" \
    || eval_param_ifn 'SOURCE_MAJOR_VERSIONS' "parse_version_major ${SOURCE_REPO_VERSIONS}"
  eval_param_ifn 'SOURCE_MINOR_VERSIONS' "parse_version_minor ${SOURCE_REPO_VERSIONS}"
}

## determine valid build targers, taking into account the versioning of the
## specific image being built
#
#  type
#    minor: build image for each 'X.Y' in version 'X.Y.Z'
#    major: build image for each 'X' in 'X.Y.Z'
#
get_target_versions () {
  case "${TARGET_VERSION_TYPE}" in
    minor)
      versions="${SOURCE_MINOR_VERSIONS}"
      ;;&
    major)
      versions="${SOURCE_MAJOR_VERSIONS}"
      ;;&
    minor|major)
      target_versions=''
      for ver in ${versions}; do
        target_versions="${target_versions}$(echo "${SOURCE_REPO_VERSIONS}" | xargs -n1 | grep -oP "(^${ver}\..*)" | sort -uV | tail -n1) "
      done
      ;;
    custom|*)
      # default to the full minor version list if there's no match
      target_versions="${TARGET_MINOR_VERSIONS}"
      ;;
  esac

  ifFuncSetVar 'target_versions' 'custom_target_versions'

  # don't build anything older than what's already in the target repo
  [ ! -z "${MINIMUM_VERSION}" ]  \
    && min_ver="${MINIMUM_VERSION}" \
    || min_ver="$(echo "${TARGET_MINOR_VERSIONS}" | xargs -n1 | tail -n +1 | head -n1)"

  log_debug "Target minimum: ${min_ver}"

  target_versions="$(echo "${min_ver} ${target_versions}" | xargs -n1 | sort -V)"
  add_param "$(echo "${target_versions#*${min_ver}}" | xargs -n1 | sort -uV | xargs)" 'TARGET_VERSIONS'
  log_debug "Target versions: ${TARGET_VERSIONS}"

  add_param "$(parse_version_major "${TARGET_VERSIONS}")" 'TARGET_MAJOR_VERSIONS'
  log_debug "Target major versions: ${TARGET_MAJOR_VERSIONS}"

  echo "${TARGET_VERSIONS}"
}

## compare versions in the target repo with versions available from the upstream
## source, determine what images should be built to upgrade to the latest source
## version
#
check_updates () {
  >&2 printf "Checking if we're up to date..\n"

  log_debug "Update target type: ${TARGET_VERSION_TYPE}"
  log_debug "Source versions:\n$(echo ${SOURCE_REPO_VERSIONS} | xargs)\n"
  log_debug "Repo versions:\n$(echo ${TARGET_REPO_VERSIONS} | xargs)\n"

  updateable=''

  case ${TARGET_VERSION_TYPE} in
    major)  vers="$(parse_version_major "${1}")"  ;;
    minor)  vers="$(parse_version_minor "${1}")"  ;;
    *)      vers="${1}"  ;;
  esac

  ifFuncSetVar 'vers' 'custom_versions' "${1}"

  log_debug "Versions: $(echo ${vers} | xargs)"

  for ver in $(echo "${vers}" | xargs -n1 | sort -uV); do
    repo_latest=''
    source_latest=''

    ifFuncSetVar 'repo_latest' 'custom_repo_latest' "${ver}"
    ifFuncSetVar 'source_latest' 'custom_source_latest' "${ver}"

    log_debug "ver: ${ver}"

    [ ! -n "${repo_latest}" ] \
      && repo_latest="$(echo "${TARGET_REPO_VERSIONS}" | grep -Po "(${ver}[\.\d]*|$)" | sort -uV | tail -n1)"
    [ ! -n "${source_latest}" ] \
      && source_latest="$(echo "${SOURCE_REPO_VERSIONS}" | grep -Po "(${ver}[\.\d]*|$)" | sort -uV | tail -n1)"

    log_debug "repo latest: ${repo_latest}"
    log_debug "source latest: ${source_latest}"

    if [ "$(printf '%s\n' "${source_latest}" "${repo_latest}" | sort -V | tail -n1)" != "${repo_latest}" ]; then
      >&2 printf "%-10s %10s -> %s\n" "${ver}" "${repo_latest}" "${source_latest}"
      updateable="${ver} $updateable"
    else
      >&2 printf "%-10s %10s matched\n" "${ver}" "${repo_latest}"
    fi

  done
  >&2 printf "\n"

  ifFuncSetVar 'updateable' 'custom_updateable_tags' "${updateable}"
  echo "${updateable}"
}

[ -z "${DO_PUSH:-}" ] && NO_PUSH='true'

if [ -n "${NOOP}" ]; then
  echo '** NOOP set. No operations will be performed.'
  echo
else
  [ -n "${NO_BUILD}" ] && echo '** NO_BUILD set. No build will be perofrmed.'
  [ -n "${NO_PUSH}" ] && echo '** NO_PUSH set. No pushes will be performed.'
  echo
fi

default_tag="${default_tag:-update}"
first_arg="${1:-$default_tag}"
all_args="${*:-$default_tag}"
log_debug "first arg: ${first_arg}"
tags=''
case "${first_arg}" in
  all_*)  tags="${!first_arg:-}"  ;;
  check|update*|all*)
    if [ ! -z "${TARGET_VERSION_TYPE}" ]; then
      # we can use the string parsing and data collection from the Docker build hooks
      # DOCKER_TAG here just sets the filename for the config.yaml
      DOCKER_TAG='update'

      . "hooks/env"

      set_repo_data
      all_tags="$(get_target_versions)"
    else
      all_tags="${all_tags}"
    fi
    ;;&
  all)
    tags="${all_tags}"
    ;;
  all-*)  # assume tags with hypens are "all-<arch>"
    for tag in ${all_tags:-}; do
      tags+="${tag}-${1##*-} "
    done
    ;;
  check|update*)
    [ ! -n "${TARGET_VERSION_TYPE}" ] \
      && echo "Checking and updating not enabled for this image." \
      && exit 1
    log_debug "Checking for updates: ${all_tags}"
    updateable="$(check_updates "${all_tags}")"
    ;;&
  check)
    printf 'Updateable: %s\n\n' "${updateable:-none}"
    exit
    ;;
  update*)
    tags="${updateable}"
    ;;
  *)
    tags="${all_args}"
    ;;
esac

tags="$(echo "${tags}" | xargs -n1 | sort -uV | xargs)"
echo "Build tags: ${tags:-none}"
echo

[ ! -n "${tags}" ] \
  && echo "Nothing to build. Exiting." \
  && exit

## first build everything
#
for DOCKER_TAG in ${tags}; do
  IMAGE_NAME="${DOCKER_REPO}:${DOCKER_TAG}"
  printf 'Building: %s\n\n' "${IMAGE_NAME}"

  . hooks/post_checkout
  [ ! -z "${SKIP_BUILD+set}" ] && echo 'Skipping build.' && continue

  . hooks/pre_build
  . hooks/build
done

## then do post-build
#
echo "--- post_build ---"
for DOCKER_TAG in ${tags}; do
  IMAGE_NAME="${DOCKER_REPO}:${DOCKER_TAG}"
  . hooks/post_build
done
echo

# 'push' or 'post-push' set this when they hit a rate limit
unset RATE_LIMITED

## then push base tags
#
if [ ! -z "${BUILD_MULTIARCH+set}" ]; then
  echo "BUILD_MULTIARCH is set, skipping push."
elif [ ! -z "${POST_PUSH_ONLY+set}" ]; then
  echo 'POST_PUSH_ONLY is set, skipping push.'
else for DOCKER_TAG in ${tags}; do
    if [ -n "${RATE_LIMITED+set}" ]; then
      PUSH_SKIPPED="${PUSH_SKIPPED} ${DOCKER_TAG}"
    else
      IMAGE_NAME="${DOCKER_REPO}:${DOCKER_TAG}"
  #    printf 'Pushing: %s\n' "${IMAGE_NAME}"
      . hooks/push
    fi
  done

  if [ -n "${PUSH_ALL_TAGS}" ]; then
    echo "--- push all tags ---"

    if [ -n "${NOOP+set}" ]; then echo '[NOOP]'
    elif [ -n "${NO_PUSH+set}" ]; then echo '[NO_PUSH]'
    else
      echo 'Pushing all tags.'
      docker push --all-tags "${DOCKER_REPO}" | grep -i digest | cut -d' ' -f3
    fi
  fi
fi
echo

## then push manifests
#
if [ -z "${PUSH_ONLY+set}" ]; then
  unset POST_PUSH_SKIPPED

  if [ ! -z "${BUILD_MULTIARCH+set}" ]; then
    echo "BUILD_MULTIARCH is set, skipping post_push."
  elif [ -n "${RATE_LIMITED+set}" ]; then
    # if RATE_LIMITED is already set by hooks/push catch it here
    # otherwise, if set by hooks/post_push, catch it in the loop
    echo 'Rate limited, skipping post_push..'
    POST_PUSH_SKIPPED="${tags}"
  else for DOCKER_TAG in ${tags}; do
    if [ -n "${RATE_LIMITED+set}" ]; then
      POST_PUSH_SKIPPED="${POST_PUSH_SKIPPED} ${DOCKER_TAG}"
    else
      IMAGE_NAME="${DOCKER_REPO}:${DOCKER_TAG}"
      # printf 'Pushing manifest: %s\n' "${IMAGE_NAME}"
      . hooks/post_push
    fi
    echo
  done fi
else
  echo 'PUSH_ONLY is set, skipping post_push.'
fi
echo

# push README.md
echo "--- README.md ---"
if [ -f "./README.md" ]; then
  if [ -n "${NO_PUSH}" ]; then
    echo 'NO_PUSH is set, not pushing README.md.'
  elif [ -n "${NO_POST_PUSH+set}" ]; then
    echo 'NO_POST_PUSH is set, not pushing README.md.'
  elif [ -n "${RATE_LIMITED+set}" ]; then
    echo 'Rate limited, not pushing README.md.'
  elif [ -n "${NOOP+set}" ]; then
    echo '[NOOP]'
  else
    echo 'Pushing README.md..'
    docker pushrm "${DOCKER_REPO}" -f ./README.md
  fi
else
  echo "No README.md to push."
fi
echo

## clean temporary files
#
# we may want to keep these files to save a few seconds on imports
if [ ! -z "${CLEAN+set}" ] || [ -z "${NO_CLEAN+set}" ]; then
  echo '--- clean ---'
  echo 'Removing temp files..'
  rm -rf _dummyfile "${QEMU_DIR}" "${IMPORTS_DIR}" >/dev/null 2>&1
  echo
fi

# remove this regardless
rm -f _dummyfile >/dev/null 2>&1

## print any pushes that were skipped
#
[ -n "${PUSH_SKIPPED}" ] && printf 'push skipped: %s\n\n' "${PUSH_SKIPPED}"
[ -n "${POST_PUSH_SKIPPED}" ] && printf 'post_push skipped: %s\n\n' "${POST_PUSH_SKIPPED}"

echo 'Done.'
echo
