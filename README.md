python -m venv .venv → .venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env + отредактировать .env
python -m app.cli init-db
python -m app.cli create-admin
python -m app.cli serve
Открыть http://127.0.0.1:8000
