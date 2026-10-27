# Actual local Python version; verify this image and Linux wheels before deployment.
FROM python:3.14.5-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 NUMEXPR_NUM_THREADS=1
RUN apt-get update && apt-get install -y --no-install-recommends libzbar0 libgl1 libglib2.0-0 gosu && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY backend/requirements-demo.lock /app/requirements-demo.lock
RUN pip install --no-cache-dir -r /app/requirements-demo.lock && pip check
RUN groupadd --gid 10001 qrshield && useradd --uid 10001 --gid 10001 --no-create-home qrshield && mkdir /data && chown 10001:10001 /data
COPY backend/ /app/backend/
COPY frontend/ /app/frontend/
COPY tools/demo-entrypoint.sh /app/demo-entrypoint.sh
RUN python /app/backend/demo_smoke.py
RUN chmod 755 /app/demo-entrypoint.sh
ENV QR_SHIELD_MODE=restricted-demo DATABASE_URL=sqlite:////data/demo.db PORT=8000
WORKDIR /app/backend
EXPOSE 8000
ENTRYPOINT ["/app/demo-entrypoint.sh"]
