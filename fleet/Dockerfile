FROM node:24-bookworm-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY server.mjs state.mjs router.mjs oauth.mjs ./
COPY public ./public
ENV FLEET_HOST=0.0.0.0 FLEET_PORT=8800 FLEET_DATA=/data
RUN mkdir -p /data && chown node:node /data
USER node
EXPOSE 8800
VOLUME /data
CMD ["node","server.mjs"]
