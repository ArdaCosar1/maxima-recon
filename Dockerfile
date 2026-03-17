FROM python:3.12-slim

WORKDIR /app

# Sistem bagimliklar
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

# Python bagimliklar
COPY requirements.txt requirements-saas.txt ./
RUN pip install --no-cache-dir -r requirements-saas.txt

# Uygulama dosyalari
COPY . .

# Rapor ve DB dizinleri
RUN mkdir -p saas_reports

# Port
EXPOSE 8000

# Calistirma
CMD ["python", "-m", "uvicorn", "saas.app:app", "--host", "0.0.0.0", "--port", "8000"]
