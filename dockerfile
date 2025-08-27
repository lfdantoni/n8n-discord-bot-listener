FROM node:22.13.1-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev
COPY . .

ENV NODE_ENV=production
# define un valor por defecto, pero se puede sobrescribir con -e PORT=XXXX
ENV PORT=3000

# usar la variable en lugar del valor fijo
EXPOSE ${PORT}

# healthcheck también con la variable
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -q -O- http://127.0.0.1:${PORT}/healthz || exit 1

CMD ["npm", "start"]