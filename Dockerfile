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