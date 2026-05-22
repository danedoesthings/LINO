FROM python:3.10-slim
RUN apt-get update && apt-get install -y default-jre-headless lua5.1 lua-socket && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . /app/
RUN pip install -r requirements.txt
ADD https://github.com/scratchminer/unluac/releases/download/v2023.03.22/unluac.jar /opt/unluac.jar
ENV UNLUAC_PATH=/opt/unluac.jar
CMD ["sh", "-c", "gunicorn -w 4 -b 0.0.0.0:${PORT} api:app"]
