FROM python:3
RUN apt-get update && apt-get -y upgrade
#RUN pip3 install --upgrade pip
RUN pip3 install protobuf
COPY . /app
WORKDIR /app
ENTRYPOINT ["python", "/app/IDSsys.py"]
