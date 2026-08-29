FROM python:3.11-slim

# Traces immédiatement visibles dans `docker compose logs`, sans buffering.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Copiées seules pour que la couche d'installation reste en cache tant que
# les dépendances ne changent pas.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt --prefer-binary

COPY . .

# Le conteneur ne tourne pas en root : une compromission de l'API ne doit pas
# donner la main sur le système de fichiers de l'image.
RUN useradd --create-home --shell /usr/sbin/nologin edr \
    && chown -R edr:edr /app
USER edr

EXPOSE 8000

# Un seul worker, volontairement : les extracteurs de features et les baselines
# sont des automates à état en mémoire de processus. Répartir les événements
# d'une même machine sur plusieurs workers fausserait fenêtres et baselines.
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
