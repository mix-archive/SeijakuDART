FROM python:alpine AS builder

RUN apk add --no-cache rust cargo

RUN --mount=type=cache,target=/root/.cache \
    pip install -U pdm

ENV PDM_CHECK_UPDATE=false
COPY pyproject.toml pdm.lock README.md /project/
COPY src/ /project/src

WORKDIR /project
RUN --mount=type=cache,target=/root/.cache \
    pdm install --check --prod --no-editable

FROM python:alpine AS runner

RUN apk add --no-cache zig upx

RUN addgroup -S app && \
    adduser -S app -G app && \
    mkdir -p /app && \
    chown app:app /app

COPY --from=builder /project/.venv /project/.venv
ENV PATH=/project/.venv/bin:$PATH

WORKDIR /app
USER app
ENTRYPOINT [ "python", "-m", "seijaku" ]

FROM runner AS exploitable

USER root

RUN apk add --no-cache su-exec

COPY src/seijaku/app/db/models.py ./hint.py
COPY ./challenge/exp.env ./.env
COPY --chown=app:app ./challenge/exp.sqlite3 ./db.sqlite3

COPY ./challenge/readflag.c ./tmp/readflag.c
RUN --mount=type=cache,target=/root/.cache \
    zig cc ./tmp/readflag.c -o ./readflag && \
    chmod u+s ./readflag

ENV FLAG=flag{this_is_a_fake_flag}
ENTRYPOINT [ "/bin/sh", "-c", "\
    echo -n $FLAG > /flag && \
    unset FLAG && \
    chown root:root /flag && \
    chmod 400 /flag && \
    exec su-exec app python -m seijaku" ]