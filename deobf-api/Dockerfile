FROM python:3.10-slim

# Download and install lune from the official GitHub releases.
RUN apt-get update && apt-get install -y curl unzip && \
    curl -fsSL https://github.com/lune-org/lune/releases/download/v0.10.4/lune-0.10.4-linux-x86_64.zip -o lune.zip && \
    unzip lune.zip && \
    mv lune /usr/local/bin/lune && \
    chmod +x /usr/local/bin/lune && \
    rm lune.zip && \
    apt-get remove -y curl unzip && apt-get autoremove -y

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["gunicorn", "-w", "1", "--threads", "4", "-b", "0.0.0.0:5000", "--timeout", "300", "api:app"]
