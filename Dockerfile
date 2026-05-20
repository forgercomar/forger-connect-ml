FROM node:20-alpine AS base
WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

# Copiar fuentes — módulos del Sprint 1 (db, auth, routes-v1, migrate) +
# Sprint 2 (ml-api, worker) + Sprint 3 (scheduler).
COPY server.js db.js auth.js routes-v1.js migrate.js ml-api.js worker.js scheduler.js ./
COPY db ./db
COPY entrypoint.sh ./
RUN chmod +x entrypoint.sh

# Crear /data con permisos para el user "node" ANTES del USER directive.
# Sin esto, EasyPanel monta el volume como root y el proceso node no puede
# escribir → EACCES en /data/mappings.json.
RUN mkdir -p /data && chown -R node:node /data
USER node

# Persistencia del archivo de mappings ml_user_id → site_url.
# EasyPanel debe montar un volume en /data para que sobreviva rebuilds.
VOLUME ["/data"]

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 3000) + '/healthz').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

# entrypoint.sh corre las migraciones idempotentemente antes de arrancar el server.
# Si la DB todavía no está accesible (pg arrancando en paralelo), retry con backoff.
CMD ["./entrypoint.sh"]
