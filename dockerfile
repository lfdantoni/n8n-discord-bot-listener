FROM node:22.13.1-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .
ENV NODE_ENV=production
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD wget -q -O- http://127.0.0.1:3000/healthz || exit 1
CMD ["npm", "start"]