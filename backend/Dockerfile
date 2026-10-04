FROM docker:28-cli AS docker_cli
FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/root/.local/bin:/usr/local/bin:${PATH}"

WORKDIR /app

COPY scripts/bootstrap_tools.sh /usr/local/bin/bootstrap_tools.sh
RUN chmod 0755 /usr/local/bin/bootstrap_tools.sh \
    && BOOTSTRAP_UPDATE_CLAMAV=false \
       BOOTSTRAP_YARA_RULES=false \
       BOOTSTRAP_INSTALL_OPTIONAL=true \
       /usr/local/bin/bootstrap_tools.sh

COPY --from=docker_cli /usr/local/bin/docker /usr/local/bin/docker

COPY backend/requirements.txt /app/requirements.txt
RUN pip install --upgrade pip \
    && pip install -r /app/requirements.txt

COPY backend /app
COPY backend/docker-entrypoint.sh /docker-entrypoint.sh

RUN DJANGO_SECRET_KEY=build-time-only python manage.py collectstatic --noinput

RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /app/var/scans /app/var/uploads /app/var/yara_rules /app/var/file_sandbox /app/var/tool_locks /app/var/logs /app/var/tmp /app/var/trivy /app/var/grype/db /var/lib/clamav \
    && chown -R appuser:appuser /app /docker-entrypoint.sh /var/lib/clamav \
    && chmod 0755 /docker-entrypoint.sh

USER appuser

EXPOSE 8000

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--access-logfile", "-"]
