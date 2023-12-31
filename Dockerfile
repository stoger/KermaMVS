FROM python:3.11.6-alpine3.18

COPY src/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY src/ .

CMD [ "rm", "peers.csv"]

CMD [ "python", "-u", "main.py" ]