#! /bin/bash

[ -z "${DO_PUSH:-}" ] && NO_PUSH='true'

if [ -n "${NOOP}" ]; then
	echo '** NOOP set. No operations will be performed.'
	echo
else
	[ -n "${NO_BUILD}" ] && echo '** NO_BUILD set. No build will be perofrmed.'
	[ -n "${NO_PUSH}" ] && echo '** NO_PUSH set. No pushes will be performed.'
	echo
fi

if [ $# -eq 0 ]; then tags="${default_tag:-}"
elif [ "${1}" = 'all' ]; then tags="${all_tags:-}"
else tags="$*"
fi

tags="$(echo "${tags}" | xargs -n1 | sort -uV | xargs)"

## first build everything
#
for DOCKER_TAG in ${tags}; do
	IMAGE_NAME="${DOCKER_REPO}:${DOCKER_TAG}"
	printf 'Building: %s\n\n' "${IMAGE_NAME}"

	. hooks/post_checkout
	. hooks/pre_build
	. hooks/build
done

## then do post-build
#
for DOCKER_TAG in ${tags}; do
	IMAGE_NAME="${DOCKER_REPO}:${DOCKER_TAG}"
	. hooks/post_build
done

## then push base tags
#
if [ -z "${POST_PUSH_ONLY+set}" ]; then
	for DOCKER_TAG in ${tags}; do
		IMAGE_NAME="${DOCKER_REPO}:${DOCKER_TAG}"
#		printf 'Pushing: %s\n' "${IMAGE_NAME}"
		. hooks/push
	done

	if [ -n "${PUSH_ALL_TAGS}" ]; then
		echo "--- push all tags ---"

		if [ -n "${NOOP+set}" ]; then echo '[NOOP]'
		elif [ -n "${NO_PUSH+set}" ]; then echo '[NO_PUSH]'
		else
			echo 'Pushing all tags.'
			docker push --all-tags "${DOCKER_REPO}" | grep -i digest | cut -d' ' -f3
			#docker push --all-tags "${DOCKER_REPO}"
		fi
	fi
else
	echo 'POST_PUSH_ONLY is set, skipping push.'
fi
echo

## then push manifests
#
if [ -z "${PUSH_ONLY+set}" ]; then
	for DOCKER_TAG in ${tags}; do
		IMAGE_NAME="${DOCKER_REPO}:${DOCKER_TAG}"
#		printf 'Pushing manifest: %s\n' "${IMAGE_NAME}"
		. hooks/post_push
	done
else
	echo 'PUSH_ONLY is set, skipping post_push.'
fi

## clean temporary files
#
[ -n "${CLEAN+set}" ] \
	&& echo '--- cleaning temporary files ---' \
	&& rm -rf _dummyfile "${QEMU_DIR}" "${IMPORTS_DIR}" >/dev/null 2>&1 \
	&& echo

rm -f _dummyfile >/dev/null 2>&1
