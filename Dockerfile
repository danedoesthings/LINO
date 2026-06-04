FROM ghcr.io/railwayapp/nixpacks:ubuntu-1745885067

WORKDIR /app

COPY . .

RUN npm install --omit=dev

ENV DISCORD_TOKEN=${DISCORD_TOKEN}
ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

CMD ["npm", "start"]
