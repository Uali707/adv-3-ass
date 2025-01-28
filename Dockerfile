# Используем официальный образ Go
FROM golang:1.21-alpine

# Устанавливаем необходимые пакеты
RUN apk add --no-cache gcc musl-dev

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем файлы с зависимостями
COPY go.mod go.sum ./

# Устанавливаем зависимости
RUN go mod download

# Копируем исходный код и статические файлы
COPY . .

# Создаем необходимые директории
RUN mkdir -p /app/public/admin
RUN mkdir -p /app/uploads

# Собираем приложение
RUN go build -o main .

# Открываем порт
EXPOSE 3000

# Запускаем приложение
CMD ["./main"] 