FROM node:22-alpine3.20 AS build
WORKDIR /usr/src/app

COPY package*.json ./

# Instalar as dependências
RUN npm install --omit=dev

COPY ./ ./

EXPOSE 3333
CMD ["node", "dist/index.js"]