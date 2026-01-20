from flask import Flask, render_template, request
from elasticsearch import Elasticsearch
import json
import os

app = Flask(__name__)

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_USER = os.getenv("ES_USER")
ES_PASSWORD = os.getenv("ES_PASSWORD")

if ES_USER and ES_PASSWORD:
    es = Elasticsearch(ES_HOST, basic_auth=(ES_USER, ES_PASSWORD))
else:
    es = Elasticsearch(ES_HOST)


@app.route("/", methods=["GET"])
def index():
    q = request.args.get("q", "").strip()
    page = int(request.args.get("page", 1))
    size = int(request.args.get("size", 10))
    page = max(page, 1)
    size = min(max(size, 1), 100)
    from_ = (page - 1) * size

    results = None
    error = None

    if q:
        try:
            body = {
                "track_total_hits": True,
                "from": from_,
                "size": size,
                "query": {
                    "simple_query_string": {
                        "query": q,
                        "fields": ["*"],
                        "default_operator": "and"
                    }
                },
                "highlight": {
                    "fields": {
                        "*": {
                            "pre_tags": ["<mark>"],
                            "post_tags": ["</mark>"],
                            "number_of_fragments": 3,
                            "fragment_size": 150
                        }
                    }
                }
            }
            resp = es.search(index="*", body=body)
            results = resp
        except Exception as exc:
            error = str(exc)

    return render_template(
        "index.html",
        q=q,
        results=results,
        error=error,
        page=page,
        size=size
    )


@app.template_filter("tojson_pretty")
def tojson_pretty(value):
    return json.dumps(value, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)