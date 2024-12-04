# syntax = docker/dockerfile:1.4.0

ARG BUILD_PYTHON_VERSION="3.11"
ARG FROM_IMAGE="moonbuggy2000/alpine-s6-python:${BUILD_PYTHON_VERSION}"

ARG BUILDER_ROOT="/builder-root"


## build the virtual environment and prepare files
#
FROM "${FROM_IMAGE}" AS builder

ARG APP_PATH="/app"
ARG BUILDER_ROOT
WORKDIR "${BUILDER_ROOT}${APP_PATH}"

ARG VIRTUAL_ENV="${APP_PATH}/venv"
ENV VIRTUAL_ENV="${VIRTUAL_ENV}" \
	PYTHONDONTWRITEBYTECODE="1" \
	PYTHONUNBUFFERED="1" \
	LIBSODIUM_MAKE_ARGS="-j4"

# use a PyPi caching proxy, if provided
ARG PYPI_INDEX="https://pypi.org/simple"
RUN (mv /etc/pip.conf /etc/pip.conf.bak 2>/dev/null || true) \
	&& printf '%s\n' '[global]' "  index-url = ${PYPI_INDEX}" \
		"  trusted-host = $(echo "${PYPI_INDEX}" | cut -d'/' -f3 | cut -d':' -f1)" \
		>/etc/pip.conf

RUN python3 -m pip install virtualenv \
	&& python3 -m virtualenv --download "${BUILDER_ROOT}${VIRTUAL_ENV}"

# Python wheels from pre_build
ARG IMPORTS_DIR=".imports"
ARG TARGETARCH
ARG TARGETVARIANT
COPY _dummyfile "${IMPORTS_DIR}/${TARGETARCH}${TARGETVARIANT}*" "/${IMPORTS_DIR}/"

# setup Python requirements
ARG AGENT_STRING=""
COPY "./requirements${AGENT_STRING}.txt" ./requirements.txt

ARG API_BACKEND="${API_BACKEND:-}"
RUN echo "${API_BACKEND}" >> ./requirements.txt

# activate virtual env
ENV ORIGINAL_PATH="$PATH"
ENV PATH="${BUILDER_ROOT}${VIRTUAL_ENV}/bin:$PATH"

# First try and build from binary wheels (provided by moonbuggy2000/python-alpine-wheels)
# because it's quick and easy. Otherwise, install software and build from source.
# Use an APK chacing proxy, if provided
ARG APK_PROXY=""
ARG SSL_LIBRARY="openssl"
ARG RUST_REQUIRED="1.41.1"
RUN if ! python3 -m pip install --only-binary=:all: --find-links "/${IMPORTS_DIR}/" -r requirements.txt; then \
		echo "ERROR: Could not build with binary wheels. Attempting to build from source.."; \
		if [ ! -z "${APK_PROXY}" ]; then \
			alpine_minor_ver="$(grep -o 'VERSION_ID.*' /etc/os-release | grep -oE '([0-9]+\.[0-9]+)')"; \
			mv /etc/apk/repositories /etc/apk/repositories.bak; \
			echo "${APK_PROXY}/alpine/v${alpine_minor_ver}/main" >/etc/apk/repositories; \
			echo "${APK_PROXY}/alpine/v${alpine_minor_ver}/community" >>/etc/apk/repositories; \
		fi \
		&& apk add --no-cache \
			"${SSL_LIBRARY}-dev" \
			cargo \
			ccache \
			gcc \
			libffi-dev \
			make \
			musl-dev \
			openssl-dev \
		#	python3-dev \
			rust; \
		RUST_VERSION="$(rustc --version | cut -d' ' -f2)"; \
		if [ "$(printf '%s\n' "${RUST_REQUIRED}" "${RUST_VERSION}" | sort -V | head -n1)" != "${RUST_REQUIRED}" ]; then \
			echo "*** CRYPTOGRAPHY_DONT_BUILD_RUST ***"; export "CRYPTOGRAPHY_DONT_BUILD_RUST=1"; fi; \
		python3 -m pip install --find-links "/${IMPORTS_DIR}/" -r requirements.txt; \
	fi

# organize files
RUN mkdir ./keys

ARG FILE_STRING="dnsmasq_updater${AGENT_STRING}"
COPY "./${FILE_STRING}.conf" ./conf/
COPY "./${FILE_STRING}.py" "./${FILE_STRING}"

WORKDIR "${BUILDER_ROOT}"

COPY ./root ./

RUN add-contenv \
		APP_PATH="${APP_PATH}" \
		FILE_STRING="${FILE_STRING}" \
		PATH="${VIRTUAL_ENV}/bin:${ORIGINAL_PATH}" \
		VIRTUAL_ENV="${VIRTUAL_ENV}" \
		PYTHONDONTWRITEBYTECODE="1" \
		PYTHONUNBUFFERED="1" \
		DMU_API_BACKEND="${API_BACKEND}" \
	&& cp /etc/contenv_extra ./etc/

## build the standalone image
#
FROM "${FROM_IMAGE}" AS standalone

ARG BUILDER_ROOT
COPY --from=builder "${BUILDER_ROOT}/" /

HEALTHCHECK --start-period=10s --timeout=10s CMD /healthcheck.sh

## build the dnsmasq-bundled image
#
FROM standalone AS dnsmasq

RUN if [ ! -z "${APK_PROXY}" ]; then \
		alpine_minor_ver="$(grep -o 'VERSION_ID.*' /etc/os-release | grep -oE '([0-9]+\.[0-9]+)')"; \
		mv /etc/apk/repositories /etc/apk/repositories.bak; \
		echo "${APK_PROXY}/alpine/v${alpine_minor_ver}/main" >/etc/apk/repositories; \
		echo "${APK_PROXY}/alpine/v${alpine_minor_ver}/community" >>/etc/apk/repositories; \
	fi \
	&& apk -U add --no-cache \
		dnsmasq \
		procps \
  && (mv -f /etc/apk/repositories.bak /etc/apk/repositories >/dev/null 2>&1 || true) \
	&& touch \
		/etc/s6-overlay/s6-rc.d/user/contents.d/dnsmasq \
		/etc/s6-overlay/s6-rc.d/dnsmasq-updater/dependencies.d/dnsmasq \
	&& cp -f healthcheck-dnsmasq.sh healthcheck.sh

ENV DMU_HOSTS_LOCATION="local" \
	DMU_HOSTS_FILE="/etc/hosts.updater" \
	DMU_RESTART_CMD="pkill -HUP dnsmasq"

## provide standalone as the default image
#
FROM standalone
