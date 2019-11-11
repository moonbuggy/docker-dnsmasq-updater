FROM python:3.8.0-slim-buster

RUN pip install docker python_hosts paramiko scp

COPY dnsmasq_updater.py /
COPY dnsmasq_updater.conf /conf/
COPY docker-entrypoint.sh /

RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]

CMD ["python", "-u", "dnsmasq_updater.py"]