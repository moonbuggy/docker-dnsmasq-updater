ARG ALPINE_VERSION=3.12.0
ARG PYTHON_VERSION=3.8
ARG APP_PATH=/app
ARG VIRTUAL_ENV=${APP_PATH}/venv

# build the virtual environment
#
FROM python:${PYTHON_VERSION}-alpine as builder

ARG VIRTUAL_ENV
ARG APP_PATH

ENV	PATH="${VIRTUAL_ENV}/bin:$PATH" \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONUNBUFFERED=1

RUN apk add --no-cache \
		gcc \
		libffi-dev \
		make \
		musl-dev \
		openssl-dev \
		py3-virtualenv

WORKDIR $APP_PATH

COPY requirements.txt ./

RUN python3 -m venv $VIRTUAL_ENV \
	&& pip3 install --no-cache-dir --upgrade pip \
	&& pip3 install --no-cache-dir -r requirements.txt \
	&& rm -f requirements.txt \
	&& ln -sf /usr/bin/python3 ${VIRTUAL_ENV}/bin/python3

RUN mkdir ${APP_PATH}/keys \
	&& mkdir ${APP_PATH}/conf

COPY ./dnsmasq_updater.py ./dnsmasq_updater
COPY ./dnsmasq_updater.conf ./conf/

# build the final image
#
FROM moonbuggy2000/alpine-s6:${ALPINE_VERSION}

ARG PYTHON_VERSION
ARG VIRTUAL_ENV
ARG APP_PATH

ENV PATH="${VIRTUAL_ENV}/bin:$PATH"

WORKDIR ${APP_PATH}

RUN apk add --no-cache \
		python3=~$PYTHON_VERSION \
	&& add-contenv \
		APP_PATH=${APP_PATH} \
		PYTHON_VERSION=${PYTHON_VERSION} \
		VIRTUAL_ENV=${VIRTUAL_ENV} \
		PYTHONPATH=${VIRTUAL_ENV}/lib/python${PYTHON_VERSION}/site-packages/ \
		PYTHONDONTWRITEBYTECODE=1 \
		PYTHONUNBUFFERED=1

COPY --from=builder ${APP_PATH}/ ./
COPY ./container/ /

ENTRYPOINT ["/init"]

HEALTHCHECK --start-period=10s --timeout=10s CMD /healthcheck.sh
