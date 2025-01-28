FROM golang:1.21-alpine

WORKDIR /app

# Копируем файлы go.mod и go.sum
COPY go.mod go.sum ./
RUN go mod download

# Копируем все файлы проекта
COPY . .

# Создаем директорию для загрузок
RUN mkdir -p /app/uploads

# Собираем приложение
RUN go build -o main .

# Открываем порт
EXPOSE 8080

# Запускаем приложение
CMD ["./main"]