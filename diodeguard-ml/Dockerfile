FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p datasets/processed models/saved data && \
    python scripts/prepare_datasets.py && \
    python models/train_all.py

CMD ["python", "pipeline/kafka_consumer.py"]
