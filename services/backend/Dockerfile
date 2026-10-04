FROM python:3.13.16-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed
WORKDIR /app
COPY services/backend/requirements.lock /app/requirements.lock
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY services/backend/tracehawk /app/tracehawk
COPY services/backend/migrations /app/migrations
COPY contracts /app/contracts
COPY evaluation/reports/summary.json /app/evaluation/reports/summary.json
COPY scenarios/phase0 /app/scenarios/phase0
COPY scenarios/phase1-benign /app/scenarios/phase1-benign
RUN useradd -u 10001 -M app && mkdir /state && chown 10001:10001 /state
USER 10001
ENV PYTHONUNBUFFERED=1
CMD ["uvicorn","tracehawk.api:app","--host","0.0.0.0","--port","8100","--no-access-log"]
