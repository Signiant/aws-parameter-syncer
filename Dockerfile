FROM jfloff/alpine-python:2.7-slim

MAINTAINER Signiant DevOps <devops@signiant.com>

ADD parameter_sync.py /parameter_sync.py
ADD parameter_sync.sh /parameter_sync.sh

RUN pip install boto3
RUN chmod a+x /parameter_sync.py /parameter_sync.sh

ENTRYPOINT ["/parameter_sync.sh"]
