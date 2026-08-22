FROM python:3.12-slim

ARG VGEN_UID=1000

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/vgen

COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src

RUN python -m pip install --no-cache-dir '.[gateway,broker,worker-comfyui]'

RUN addgroup --system vgen \
    && adduser --system --uid "${VGEN_UID}" --ingroup vgen --home /var/lib/vgen vgen \
    && mkdir -p /var/lib/vgen \
    && chown -R vgen:vgen /var/lib/vgen

USER vgen
WORKDIR /var/lib/vgen

CMD ["vgen-gateway", "--database", "/var/lib/vgen/vgen-gateway.db", "serve", "--host", "0.0.0.0", "--port", "8000"]
