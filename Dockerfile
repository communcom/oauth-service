FROM node:12-alpine as builder

WORKDIR /app

COPY package*.json ./

RUN npm install --only=production

FROM node:12-alpine

ENV NODE_ENV=production
WORKDIR /app

COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules/ ./node_modules/

COPY ./src/ ./src
COPY *p8 ./
CMD [ "node", "./src/app.js" ]
