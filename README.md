# Flask Elasticsearch 全文检索

一个用于 Elasticsearch 7.7 的 Flask 查询界面，支持全文检索与高亮展示。

## 环境要求

- Python 3.8+
- Elasticsearch 7.7

## 安装

```bash
python -m venv .venv
source .venv/bin/activate  # Windows 使用 .venv\Scripts\activate
pip install -r requirements.txt
```

## 运行

```bash
export ES_HOST=http://localhost:9200
# 如果有账号密码：
# export ES_USER=elastic
# export ES_PASSWORD=your_password
python app.py
```

浏览器访问：`http://localhost:5000`

## 说明

- 查询接口使用 `simple_query_string`，对所有字段进行全文检索
- 默认查询所有索引：`index="*"`
- 高亮标记使用 `<mark>` 标签
