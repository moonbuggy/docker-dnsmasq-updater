ARG PYTHON_VERSION="3.8"
ARG APP_PATH="/app"
ARG VIRTUAL_ENV="${APP_PATH}/venv"
ARG BUILDER_ROOT="/builder-root"

ARG FROM_IMAGE="moonbuggy2000/alpine-s6-python:${PYTHON_VERSION}"

ARG SSL_LIBRARY="openssl"

ARG TARGET_ARCH_TAG="arm64"

## build the virtual environment and prepare files
#
FROM "${FROM_IMAGE}" AS builder

# QEMU static binaries from pre_build
ARG QEMU_DIR
ARG QEMU_ARCH
COPY _dummyfile "${QEMU_DIR}/qemu-${QEMU_ARCH}-static*" /usr/bin/

# these only need to be installed if we're building modules, but since the musl wheels aren't
# automatically kept updated we leave the build environment installed so we're capable of
# running independently if/when PyPi wants to install newer versions that the pre-built wheels
ARG SSL_LIBRARY
RUN apk -U add --no-cache \
		"${SSL_LIBRARY}-dev" \
		cargo \
		ccache \
		gcc \
		libffi-dev \
		make \
		musl-dev \
		openssl-dev \
		python3-dev \
		rust

ARG APP_PATH
ARG BUILDER_ROOT
WORKDIR "${BUILDER_ROOT}${APP_PATH}"

ARG VIRTUAL_ENV
ENV	VIRTUAL_ENV="${VIRTUAL_ENV}" \
	PYTHONDONTWRITEBYTECODE="1" \
	PYTHONUNBUFFERED="1" \
	LIBSODIUM_MAKE_ARGS="-j4"

RUN python3 -m pip install --upgrade virtualenv \
	&& python3 -m virtualenv --download "${BUILDER_ROOT}${VIRTUAL_ENV}"

COPY ./requirements.txt ./

# Python wheels from pre_build
ARG TARGET_ARCH_TAG
ARG IMPORTS_DIR=".imports"
COPY _dummyfile "${IMPORTS_DIR}/${TARGET_ARCH_TAG}*" "/${IMPORTS_DIR}/"

# activate virtual env
ENV ORIGINAL_PATH="$PATH"
ENV PATH="${BUILDER_ROOT}${VIRTUAL_ENV}/bin:$PATH"

# retain the ability to build from source for all arches
ARG RUST_REQUIRED
RUN RUST_VERSION="$(rustc --version | cut -d' ' -f2)" \
	&& if [ "${QEMU_ARCH}" = 'arm' ] \
		|| [ "$(printf '%s\n' "${RUST_REQUIRED}" "${RUST_VERSION}" | sort -V | head -n1)" != "${RUST_REQUIRED}" ]; then \
			echo "*** CRYPTOGRAPHY_DONT_BUILD_RUST"; export "CRYPTOGRAPHY_DONT_BUILD_RUST=1"; fi \
	&& python3 -m pip install --only-binary=:all: --find-links "/${IMPORTS_DIR}/"  -r requirements.txt \
	|| python3 -m pip install --find-links "/${IMPORTS_DIR}/" -r requirements.txt

# lose the ability to build from source on all arches
#RUN python3 -m pip install --only-binary=:all: --find-links "/${IMPORTS_DIR}/"  -r requirements.txt \
#	|| python3 -m pip install --find-links "/${IMPORTS_DIR}/" -r requirements.txt

# organize files
RUN mkdir ./keys \
	&& mkdir ./conf

COPY ./dnsmasq_updater.conf ./conf/
COPY ./dnsmasq_updater.py ./dnsmasq_updater

WORKDIR "${BUILDER_ROOT}"

COPY ./root ./

RUN add-contenv \
		APP_PATH="${APP_PATH}" \
		PATH="${VIRTUAL_ENV}/bin:${ORIGINAL_PATH}" \
		VIRTUAL_ENV="${VIRTUAL_ENV}" \
		PYTHONDONTWRITEBYTECODE="1" \
		PYTHONUNBUFFERED="1" \
	&& cp /etc/contenv_extra ./etc/

## build the final image
#
FROM "${FROM_IMAGE}"

ARG BUILDER_ROOT
COPY --from=builder "${BUILDER_ROOT}/" /

HEALTHCHECK --start-period=10s --timeout=10s CMD /healthcheck.sh
