FROM python:3

WORKDIR /usr/src/app

COPY . .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir netaddr pyjwt


ENTRYPOINT ["python", "./kusimamia.py"]
