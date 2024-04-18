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
ENV	VIRTUAL_ENV="${VIRTUAL_ENV}" \
	PYTHONDONTWRITEBYTECODE="1" \
	PYTHONUNBUFFERED="1" \
	LIBSODIUM_MAKE_ARGS="-j4"

RUN python3 -m pip install --upgrade virtualenv \
	&& python3 -m virtualenv --download "${BUILDER_ROOT}${VIRTUAL_ENV}"

# setup Python requirements
ARG AGENT_STRING=''
COPY "./requirements${AGENT_STRING}.txt" ./requirements.txt

ARG API_BACKEND="${API_BACKEND:-}"
RUN echo "${API_BACKEND}" >> ./requirements.txt

# Python wheels from pre_build
ARG TARGET_ARCH_TAG="amd64"
ARG IMPORTS_DIR=".imports"
COPY _dummyfile "${IMPORTS_DIR}/${TARGET_ARCH_TAG}*" "/${IMPORTS_DIR}/"

# activate virtual env
ENV ORIGINAL_PATH="$PATH"
ENV PATH="${BUILDER_ROOT}${VIRTUAL_ENV}/bin:$PATH"

# First try and build from binary wheels (provided by moonbuggy2000/python-alpine-wheels)
# because it's quick and easy. Otherwise, install software and build from source.
ARG SSL_LIBRARY="openssl"
ARG RUST_REQUIRED="1.41.1"
RUN if ! python3 -m pip install --only-binary=:all: --find-links "/${IMPORTS_DIR}/" -r requirements.txt; then \
			echo "ERROR: Could not build with binary wheels. Attempting to build from source.."; \
			apk add --no-cache \
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


## build the final image
#
FROM "${FROM_IMAGE}"

ARG BUILDER_ROOT
COPY --from=builder "${BUILDER_ROOT}/" /

ENV S6_CMD_WAIT_FOR_SERVICES_MAXTIME=0

HEALTHCHECK --start-period=10s --timeout=10s CMD /healthcheck.sh
