FROM python:3.12-slim
LABEL org.opencontainers.image.title="cognis-ghaudit"
LABEL org.opencontainers.image.source="https://github.com/cognis-digital/ghaudit"
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .
ENTRYPOINT ["ghaudit"]
