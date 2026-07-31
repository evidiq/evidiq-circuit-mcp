# Multi-stage build for EVIDIQ Circuit MCP
FROM node:22-alpine AS builder

WORKDIR /app

COPY package*.json ./
COPY tsconfig.json ./

RUN npm ci

COPY . .

RUN npm run build

FROM node:22-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

COPY package*.json ./
RUN npm ci --only=production

COPY --from=builder /app/dist ./dist
COPY skill.md ./skill.md
COPY scripts ./scripts

EXPOSE 3000

CMD ["node", "dist/start-server.js"]
