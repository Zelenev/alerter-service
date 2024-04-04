FROM python
WORKDIR /alerter
ENV ELASTIC_PASSWORD=changeme
ENV TIME_RANGE=60
ENV ELASTIC_HOST=elastichost
COPY requirements.txt /alerter
RUN pip3 install --upgrade pip -r requirements.txt
COPY . .
EXPOSE 8080
CMD ["python", "app.py"]