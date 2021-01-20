FROM nginx:latest
WORKDIR /proj

RUN apt-get update
RUN apt-get -y install libpython3-dev
RUN apt-get -y install python3-pip

ADD app.py .
ADD requirements.txt .
ADD .env .
ADD app.ini .
ADD wsgi.py .
COPY /templates /proj/templates
COPY /static /proj/static
COPY config/default.conf ../etc/nginx/conf.d/default.conf
COPY config/nginx.conf ../etc/nginx/nginx.conf
COPY ssl/nginx-selfsigned.crt ../etc/ssl/certs/nginx-selfsigned.crt
COPY ssl/nginx-selfsigned.key ../etc/ssl/private/nginx-selfsigned.key

RUN python3 -m pip install wheel
RUN python3 -m pip install -r requirements.txt
RUN python3 -m pip install uwsgi


