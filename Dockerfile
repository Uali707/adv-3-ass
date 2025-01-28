# Используем официальный образ Golang
FROM golang:1.21-alpine

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем файлы с зависимостями
COPY go.mod go.sum ./

# Скачиваем зависимости
RUN go mod download

# Копируем исходный код
COPY . .

# Собираем приложение
RUN go build -o main .

# Открываем порт
EXPOSE 3000

# Запускаем приложение
CMD ["./main"] 