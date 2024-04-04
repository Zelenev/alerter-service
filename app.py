from flask import Flask, render_template, jsonify, request, redirect
from flask_apscheduler import APScheduler
from elasticsearch import Elasticsearch
import json
import yaml
from dotenv import load_dotenv
import os
import prison
from datetime import datetime, timedelta

app = Flask(__name__)
scheduler = APScheduler()
load_dotenv()

# elastic cred
ELASTIC_PASSWORD = os.getenv('ELASTIC_PASSWORD')
ELASTIC_HOST = os.getenv('ELASTIC_HOST')
def elastic_query():

    es = Elasticsearch(f"http://elastic:{ELASTIC_PASSWORD}@{ELASTIC_HOST}:9200")

    # забираем правила из индекса
    rules = es.search(index="alerter-rules")['hits']['hits']

    if not rules:
        print("Индекс пуст!")
    else:
        for item in rules:

            rule = item["_source"]["bool"]
            rule_name = item["_source"]["title"]
            description = item["_source"]["description"]
            author = item["_source"]["author"]
            level = item["_source"]["level"]
            references = item["_source"]["references"]
            rule_index = item["_source"]["index"]
            severity = item["_source"]["severity"]
            rule_type = item["_source"]["condition"]["type"]

            if rule_type == "list":
                # Задается шаблон для поиска и фильтра по времени, в него подставляется правило (rule)
                template = "{'query': {'bool': {'must': [{'bool': "+str(rule)+"}], 'filter': [{'range': {'@timestamp': {'gt': 'now-"+str(os.getenv('TIME_RANGE'))+"s'}}}]}}}"

                # Меняем одинарные кавычки на двойные, потому что по-другому не хавает в json, далее закатываем в json
                search = json.loads(template.replace("'", '"'))

                # Кидаем запрос на поиск по индексу и запросу
                response = es.search(index=rule_index, body=search, size=50)['hits']['hits']

                if not response:
                    # print("Нет событий, удовлетворяющих правилу: " + rule_name + " " + rule_type)
                    pass
                else:
                    for hit in response:
                        index_name = hit["_index"]
                        link = "http://192.168.3.101:5601/app/discover#/doc/f5ae0bc0-d9bb-11ee-8082-27bc8f6a5ed7/" + index_name + "?id="+ hit["_id"]

                        rule_message = hit["_source"]["message"]
                        timestamp = hit["_source"]["@timestamp"]

                        # индекс, имя правила, мэссэдж, ссылка
                        document = {"timestamp": timestamp, "alerter.index_name": index_name, "alerter.author": author,
                                    "alerter.level": level, "alerter.references": references,
                                    "alerter.rule_name": rule_name, "alerter.description": description,
                                    "message": rule_message,"alerter.severity": severity, "alerter.source_url": link}

                        # добавляем сработку в индекс алертера
                        alert = es.index(index="alerter", body=document)
                        print("Статус новой заявки по правилу '"+ rule_name +"': " + alert['result'])

            elif rule_type == "bucket":

                bucket = item["_source"]["condition"]["aggs"]
                template = "{'query': {'bool': {'must': [{'bool': " + str(rule) + "}], 'filter': [{'range': {'@timestamp': {'gt': 'now-15m'}}}]}},'aggs': " + str(bucket) +" }"
                search = json.loads(template.replace("'", '"'))

                response = es.search(index=rule_index, body=search, size=50)

                if not response["aggregations"]:
                    print("Ошибка в правиле: "+ rule_name)
                    # pass
                else:
                    bucket_list = response["aggregations"]["host.name"]["buckets"]

                    if not bucket_list:

                        # print("Бакет для правила "+rule_name+" пуст!")
                        pass

                    else:
                        current_time = datetime.now()
                        paste_time = current_time - timedelta(minutes=30)
                        rison_query = prison.dumps(rule)

                        timestamp = response["hits"]["hits"][0]["_source"]["@timestamp"]

                        link = "http://192.168.3.101:5601/app/kibana#/discover?_g=(time:(from:'"+ str(paste_time) +"',mode:absolute,to:'"+ str(current_time) +"'))&_a=(columns:!(host.name),filters:!((bool:" + str(rison_query) + "%2Cmeta:())),index:'2fd36450-db9f-11ee-9f4c-abf789d83414',interval:auto,query:(language:lucene,query:''),sort:!(timestamp,desc))"

                        document = {"timestamp": timestamp, "alerter.index_name": rule_index, "alerter.author": author,
                                    "alerter.level": level, "alerter.references": references,
                                    "alerter.rule_name": rule_name, "alerter.description": description,
                                    "message": "Сработало правило: "+rule_name, "alerter.severity": severity, "alerter.source_url": link}

                        # добавляем сработку в индекс алертера
                        alert = es.index(index="alerter", body=document)
                        print("Статус новой заявки по правилу '" + rule_name + "': " + alert['result'])

@app.route('/', methods=['GET'])
def get_alerter_info():

    es = Elasticsearch(f"http://elastic:{ELASTIC_PASSWORD}@{ELASTIC_HOST}:9200")
    count = es.count(index="alerter-rules")["count"]

    version = {"Version": 1.0, "Name": "Alerter-Service", "Number of rules": count}
    return version

@app.route('/rules', methods=['GET'])
def get_rules_list():

    es = Elasticsearch(f"http://elastic:{ELASTIC_PASSWORD}@{ELASTIC_HOST}:9200")
    rules = es.search(index="alerter-rules")['hits']['hits']

    list_rules = {}
    for hit in rules:
        title = hit['_source']['title']
        list_rules[title] = hit['_source']['description']

    return render_template("rules.html", list_rules=list_rules)

@app.route('/upload', methods=['GET','POST'])
def upload_rule():
    if request.method == "POST":
        if request.files:
            content = request.files.get("file").read()

            if content:
                jsondump = json.dumps(yaml.safe_load(content), ensure_ascii=False).encode('utf8')
                upload = jsondump.decode()
                rule_id = json.loads(upload)["id"]

                es = Elasticsearch(f"http://elastic:{ELASTIC_PASSWORD}@{ELASTIC_HOST}:9200")
                add = es.index(index="alerter-rules", body=upload, id=rule_id)

                return "Status: " + add["result"]
            else:
                return "Uploaded Unsuccessful"

    return render_template("upload.html")

if __name__ == '__main__':
    scheduler.add_job(id='elastic task', func=elastic_query, trigger='interval', seconds=int(os.getenv('TIME_RANGE')))
    scheduler.start()
    app.run(host='0.0.0.0', port=8080)