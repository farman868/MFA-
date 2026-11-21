FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && useradd --uid 10001 --create-home bridge \
 && mkdir -p /var/log/mfa && chown bridge /var/log/mfa
COPY app ./app
USER bridge
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=12 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=2).status==200 else 1)"
# Single worker on purpose: OTP challenges and rate-limit counters are held in memory.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"]
