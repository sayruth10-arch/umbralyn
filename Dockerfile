FROM python:3.12-slim

# nmap + dépendances système de WeasyPrint (rendu PDF)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Les rapports et l'historique sortent dans un volume monté par l'utilisateur
VOLUME ["/app/reports"]

ENTRYPOINT ["python", "-m", "umbralyn"]
CMD ["--help"]
