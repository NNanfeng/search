# Flask Elasticsearch 全文检索

一个用于 Elasticsearch 7.7 的 Flask 查询界面，支持全文检索、高亮展示、用户认证和审计日志。

## 特性

- 🔍 全文检索：支持多索引、多字段搜索，自动高亮匹配内容
- 🎨 黑客风格界面：Matrix 代码雨背景效果
- 🔐 用户认证系统：基于 SQLite 的账号管理，支持登录/登出
- 📊 查询历史：客户端本地存储，所有用户可见
- 🔒 审计日志：记录所有查询操作（用户、查询内容、时间、IP、结果摘要），仅管理员可见
- 👥 用户管理：管理员可添加、删除用户，重置密码
- 🔑 密码管理：用户可修改自己的密码

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
# 可选：设置 Flask 密钥
# export SECRET_KEY=your-secret-key
python app.py
```

浏览器访问：`http://localhost:5000`

## 默认账号

首次运行会自动创建默认管理员账号：
- 用户名：`admin`
- 密码：`admin123`

**请在首次登录后立即修改密码！**

## 功能说明

### 搜索功能
- 查询接口使用 `simple_query_string`，对所有字段进行全文检索
- 默认查询所有索引：`index="*"`
- 高亮标记使用 `<mark>` 标签
- 支持分页浏览结果
- 查询历史自动保存在浏览器本地

### 管理后台
管理员登录后可访问 `/admin` 路径，包含以下功能：

1. **用户管理**：添加新用户、删除用户、重置用户密码
2. **审计日志**：查看所有用户的查询记录，包括：
   - 查询用户
   - 查询内容
   - 查询时间
   - 来源 IP
   - 结果数量
   - 查询耗时
   - 错误信息（如有）
3. **修改密码**：修改当前登录账号的密码

## 数据存储

- 用户数据和审计日志存储在 `search.db`（SQLite 数据库）
- 数据库文件已在 `.gitignore` 中排除，不会提交到版本控制
