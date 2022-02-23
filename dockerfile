FROM python:3.9.7

WORKDIR /app

RUN pip3 install flask==1.1.2
RUN pip3 install Flask-HTTPAuth==4.4.0
RUN pip3 install xmltodict==0.12.0
RUN pip3 install Werkzeug==0.16.1
RUN pip3 install ipaddress==1.0.23


COPY . .

CMD ["python3", "mock_server.py"]