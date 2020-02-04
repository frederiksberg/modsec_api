FROM python:3.8.1-alpine3.11

RUN apk add --no-cache --virtual .build-deps musl-dev postgresql-dev libc-dev gcc

RUN apk add --no-cache postgresql-libs

RUN pip install --upgrade pip

COPY ./requirements.txt /opt/requirements.txt

RUN pip install -r /opt/requirements.txt

RUN apk --purge del .build-deps

COPY ./src/flask /srv/server

WORKDIR /srv/server

CMD ["gunicorn", "-w 4", "-b 0.0.0.0:5000", "run:app"]
