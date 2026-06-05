FROM python:3.10-slim
RUN apt-get update && apt-get install -y \
default-jre-headless \
curl \
unzip \
git \
lua5.1 \
lua5.1-dev \
liblua5.1-0-dev \
build-essential \
pkg-config \
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
COPY . /app/
RUN pip install --no-cache-dir -r requirements.txt
RUN git clone https://github.com/Renbex0/Virtual-Machine.git /app/renbex0
ADD https://github.com/scratchminer/unluac/releases/download/v2023.03.22/unluac.jar /opt/unluac.jar
ENV UNLUAC_PATH=/opt/unluac.jar
ENV PATH="/usr/bin:${PATH}"
ENV LUA_PATH="/app/?.lua;/app/?/init.lua;./?.lua;./?/init.lua"
ENV LUA_CPATH="/app/?.so;./?.so"
CMD ["sh", "-c", "gunicorn -w 1 --threads 8 -b 0.0.0.0:${PORT} --timeout 300 --graceful-timeout 30 api:app"]
