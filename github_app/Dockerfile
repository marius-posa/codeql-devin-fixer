FROM python:3.11-slim

WORKDIR /app

COPY github_app/requirements.txt /app/github_app/requirements.txt
RUN pip install --no-cache-dir -r /app/github_app/requirements.txt

COPY scripts/ /app/scripts/
COPY github_app/ /app/github_app/
COPY playbooks/ /app/playbooks/

EXPOSE 3000

CMD ["python", "-m", "github_app.main"]
