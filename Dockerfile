FROM node:20-alpine AS base
WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY server.js ./

USER node

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:3000/healthz').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "server.js"]
