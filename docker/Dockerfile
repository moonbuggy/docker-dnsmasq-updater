ARG ALPINE_VERSION="3.13"
ARG PYTHON_VERSION="3.8"
ARG APP_PATH="/app"
ARG VIRTUAL_ENV="${APP_PATH}/venv"
ARG BUILDER_ROOT="/builder-root"

ARG FROM_IMAGE="moonbuggy2000/alpine-s6:${ALPINE_VERSION}"

## build the virtual environment and prepare files
#
FROM "python:${PYTHON_VERSION}-alpine${ALPINE_VERSION}" as builder

ARG APP_PATH
ARG BUILDER_ROOT
ARG VIRTUAL_ENV

ENV	PATH="${VIRTUAL_ENV}/bin:$PATH" \
	PYTHONDONTWRITEBYTECODE="1" \
	PYTHONUNBUFFERED="1" \
	LIBSODIUM_MAKE_ARGS="-j4"

RUN apk -U add --no-cache \
		cargo \
		ccache \
		gcc \
		libffi-dev \
#		libseccomp \
		make \
		musl-dev \
		openssl-dev \
		py3-virtualenv \
		py3-wheel \
		rust

WORKDIR "${APP_PATH}"

COPY ./requirements.txt ./

RUN RUST_VERSION="$(rustc --version | cut -d' ' -f2)" \
	&& RUST_REQUIRED="1.41.1" \
	&& if [ "$(printf '%s\n' "${RUST_REQUIRED}" "${RUST_VERSION}" | sort -V | head -n1)" != "${RUST_REQUIRED}" ]; then \
		echo "*** CRYPTOGRAPHY_DONT_BUILD_RUST"; export "CRYPTOGRAPHY_DONT_BUILD_RUST=1"; fi \
	&& python3 -m venv "${VIRTUAL_ENV}" \
	&& pip3 install --no-cache-dir --upgrade pip \
	&& pip3 install --no-cache-dir -r requirements.txt \
	&& rm -f requirements.txt \
	&& ln -sf /usr/bin/python3 "${VIRTUAL_ENV}/bin/python3"

WORKDIR "${BUILDER_ROOT}${APP_PATH}"

RUN mkdir ./keys \
	&& mkdir ./conf \
	&& cp -r "${APP_PATH}" "${BUILDER_ROOT}"

COPY ./dnsmasq_updater.conf ./conf/
COPY ./dnsmasq_updater.py ./dnsmasq_updater
COPY ./docker/root/ "${BUILDER_ROOT}"

## build the final image
#
FROM "${FROM_IMAGE}"

ARG PYTHON_VERSION
ARG VIRTUAL_ENV
ARG APP_PATH

ENV PATH="${VIRTUAL_ENV}/bin:$PATH"

WORKDIR "${APP_PATH}"

RUN apk -U add --no-cache \
		python3=~"${PYTHON_VERSION}" \
	&& add-contenv \
		APP_PATH="${APP_PATH}" \
		PYTHON_VERSION="${PYTHON_VERSION}" \
		VIRTUAL_ENV="${VIRTUAL_ENV}" \
		PYTHONPATH="${VIRTUAL_ENV}/lib/python${PYTHON_VERSION}/site-packages/" \
		PYTHONDONTWRITEBYTECODE="1" \
		PYTHONUNBUFFERED="1"

ARG BUILDER_ROOT
COPY --from=builder "${BUILDER_ROOT}/" /

ENTRYPOINT ["/init"]

HEALTHCHECK --start-period=10s --timeout=10s CMD /healthcheck.sh
