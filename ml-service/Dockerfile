FROM python:3.12-slim
WORKDIR /app
COPY ml-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ml-service/threatlens_ml ./threatlens_ml
COPY data/sample /data/sample
# Train the Isolation Forest on the bundled benign flows at build time (~5s).
RUN python -m threatlens_ml.train --csv /data/sample/cicids2017_sample.csv
RUN useradd --system --uid 10001 threatlens
USER threatlens
EXPOSE 8000
CMD ["uvicorn", "threatlens_ml.app:app", "--host", "0.0.0.0", "--port", "8000"]
