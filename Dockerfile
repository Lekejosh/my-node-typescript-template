FROM node:alpine

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm ci

COPY . .

EXPOSE 8080

RUN npm run build

CMD ["npm", "run", "dev"]
