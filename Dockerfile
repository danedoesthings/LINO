FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -L https://github.com/lune-org/lune/releases/download/v0.8.0/lune-0.8.0-linux-x86_64.zip \
    -o /tmp/lune.zip && \
    unzip /tmp/lune.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/lune && \
    rm /tmp/lune.zip

RUN curl -L https://github.com/seaofvoices/darklua/releases/download/v0.14.0/darklua-linux-x86_64.zip \
    -o /tmp/darklua.zip && \
    unzip /tmp/darklua.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/darklua && \
    rm /tmp/darklua.zip

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV LUNE_PATH=/usr/local/bin/lune
ENV DARKLUA_PATH=/usr/local/bin/darklua

CMD ["python", "bot.py"]
