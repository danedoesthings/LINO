FROM python:3.10-slim

RUN apt-get update && apt-get install -y default-jre-headless curl unzip && \
    rm -rf /var/lib/apt/lists/*

RUN curl -L https://github.com/lune-org/lune/releases/download/v0.8.0/lune-0.8.0-linux-x86_64.zip \
    -o /tmp/lune.zip && \
    unzip /tmp/lune.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/lune && \
    rm /tmp/lune.zip

WORKDIR /app
COPY . /app/
RUN pip install -r requirements.txt
RUN python download_renbex.py

ADD https://github.com/scratchminer/unluac/releases/download/v2023.03.22/unluac.jar /opt/unluac.jar
ENV UNLUAC_PATH=/opt/unluac.jar

CMD ["sh", "-c", "gunicorn -w 4 -b 0.0.0.0:${PORT} api:app"]
