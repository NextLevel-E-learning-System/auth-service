FROM node:22-alpine3.20
WORKDIR /usr/src/app

COPY package*.json ./
# Instalar todas as dependências primeiro
RUN npm install

COPY ./ ./
# Fazer o build do TypeScript
RUN npm run build

# Remover dependências dev após o build
RUN npm prune --omit=dev

EXPOSE 3333
CMD ["node", "dist/index.js"]