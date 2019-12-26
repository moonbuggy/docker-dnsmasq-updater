ARG PYTHON_VERSION=3.7
ARG APP_PATH=/app
ARG VIRTUAL_ENV=${APP_PATH}/venv

# build the virtual environment
#
FROM python:${PYTHON_VERSION}-alpine as builder

ARG VIRTUAL_ENV
ARG APP_PATH

ENV PATH="${VIRTUAL_ENV}/bin:$PATH" \
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
	&& pip install --no-cache-dir --upgrade pip \
	&& pip3 install --no-cache-dir -r requirements.txt \
	&& rm -f requirements.txt \
	&& ln -sf /usr/bin/python3 ${VIRTUAL_ENV}/bin/python3

COPY dnsmasq_updater.py ./

# build the final image
#
FROM moonbuggy2000/alpine-s6:3.10.3

ARG PYTHON_VERSION
ARG VIRTUAL_ENV
ARG APP_PATH

ENV	APP_PATH="${APP_PATH}" \
	PATH="${VIRTUAL_ENV}/bin:$PATH" \
	PYTHONPATH="${VIRTUAL_ENV}/lib/python${PYTHON_VERSION}/site-packages/" \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONUNBUFFERED=1

RUN apk add --no-cache \
		python3=~$PYTHON_VERSION

WORKDIR ${APP_PATH}

COPY --from=builder ${APP_PATH}/ ./
COPY ./container/ /
COPY ./dnsmasq_updater.conf /conf/

ENTRYPOINT ["/init"]

HEALTHCHECK --start-period=30s --timeout=10s CMD ${APP_PATH}/healthcheck.sh
