FROM python:3.12-slim-bookworm

ENV PYTHONUTF8=1 PYTHONUNBUFFERED=1 POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1 PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
RUN apt-get update \
    && apt-get install -y --no-install-recommends nftables iproute2 wireguard-tools iputils-ping openssh-server openssh-client pipx \
    && pipx install poetry==2.4.1 --python /usr/local/bin/python \
    && apt-get clean
WORKDIR /app
COPY pyproject.toml poetry.lock README.md ./
RUN poetry install --only main --no-root
COPY src ./src
RUN poetry install --only main
COPY lab/server.py ./lab/server.py
COPY lab/professional ./lab/professional
ENV PATH="/app/.venv/bin:$PATH"
CMD ["sleep", "infinity"]
