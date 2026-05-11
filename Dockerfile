FROM node:24-alpine AS build

WORKDIR /app

COPY package.json package-lock.json* ./
COPY packages/core/package.json packages/core/
COPY packages/cli/package.json packages/cli/
COPY packages/control-plane/package.json packages/control-plane/

RUN npm ci

COPY . .

RUN npm run build
RUN npm prune --production

FROM node:24-alpine AS runtime

WORKDIR /app

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/packages ./packages
COPY --from=build /app/config ./config

EXPOSE 53/udp 53/tcp 80/tcp 443/tcp

RUN addgroup -S zonzon && adduser -S zonzon -G zonzon
USER zonzon

ENTRYPOINT ["node", "packages/cli/dist/cli.js"]
CMD ["--config", "/app/config/hosts.json", "--port", "53"]