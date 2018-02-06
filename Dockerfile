FROM python:3

RUN DEBIAN_FRONTEND=noninteractive apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install genisoimage isolinux \
    syslinux syslinux-utils


WORKDIR /usr/src/app

COPY . .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir netaddr pyjwt


ENTRYPOINT ["python", "./meneja.py"]
