FROM golang:1.21-alpine

WORKDIR /app

# Установка необходимых пакетов
RUN apk update && apk add --no-cache git gcc musl-dev

# Копируем только go.mod и go.sum сначала
COPY go.mod .
COPY go.sum .

# Скачиваем зависимости
RUN go mod download && go mod verify

# Копируем остальные файлы проекта
COPY . .

# Собираем приложение
RUN go build -o main .

# Открываем порт
EXPOSE 8080

# Запускаем приложение
CMD ["./main"]