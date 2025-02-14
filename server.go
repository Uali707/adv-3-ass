package main

import (
	"bytes"
	"context"

	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
	"gopkg.in/gomail.v2"
	"html/template" // Добавьте этот импорт для шаблонов
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"

	"strconv"
	"strings"
	"syscall"
	"time"
)

// Структура для хранения данных о действиях пользователей
type UserActionLog struct {
	ID        int       `json:"id"`
	UserIP    string    `json:"user_ip"`
	UserAgent string    `json:"user_agent"`
	Endpoint  string    `json:"endpoint"`
	Method    string    `json:"method"`
	Action    string    `json:"action"`
	Params    string    `json:"params"`
	CreatedAt time.Time `json:"created_at"`
}

// Добавляем эти структуры перед структурой User
type Permission struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"`
	Name        string             `bson:"name"`
	Description string             `bson:"description"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Role struct {
	ID          primitive.ObjectID `bson:"_id" json:"_id"`
	Name        string             `bson:"name" json:"name"`
	Description string             `bson:"description"`
	Permissions []Permission       `bson:"permissions"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Структура пользователя
type User struct {
	ID              primitive.ObjectID   `bson:"_id" json:"_id"`
	Email           string               `bson:"email" json:"email"`
	Password        string               `bson:"password" json:"-"` // Не отправляем пароль клиенту
	CreatedAt       time.Time            `bson:"created_at" json:"created_at"`
	UpdatedAt       time.Time            `bson:"updated_at" json:"updated_at"`
	OTP             string               `bson:"otp,omitempty" json:"-"`
	OTPExpiresAt    time.Time            `bson:"otp_expires_at,omitempty" json:"-"`
	TempToken       string               `bson:"temp_token,omitempty" json:"-"`
	RoleIDs         []primitive.ObjectID `bson:"role_ids" json:"role_ids"`
	IsEmailVerified bool                 `bson:"is_email_verified" json:"is_email_verified"`
}

var logFile = "activity_logs.json" // Путь к файлу логов
var logID = 1                      // Счётчик для ID записи

// Функция для записи логов в файл
func logToFile(logEntry UserActionLog) {
	// Открываем файл для добавления логов (создаем, если его нет)
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.WithError(err).Error("Failed to open log file")
		return
	}
	defer file.Close()

	// Преобразуем запись в JSON
	logEntry.ID = logID // Присваиваем ID
	logID++             // Увеличиваем ID для следующей записи
	logData, err := json.Marshal(logEntry)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal log entry")
		return
	}

	// Записываем JSON в файл
	if _, err := file.WriteString(string(logData) + "\n"); err != nil {
		logger.WithError(err).Error("Failed to write log entry to file")
	}
}

// Обновляем структуру Device
type Device struct {
	ID      primitive.ObjectID `bson:"_id" json:"_id"`
	Name    string             `bson:"name" json:"name"`
	Price   float64            `bson:"price" json:"price"`
	Catalog string             `bson:"catalog" json:"catalog"`
}

// Исправляем структуру SupportMessage для MongoDB
type SupportMessage struct {
	ID         primitive.ObjectID `bson:"_id,omitempty"`
	UserEmail  string             `bson:"user_email"`
	Subject    string             `bson:"subject"`
	Message    string             `bson:"message"`
	Attachment string             `bson:"attachment"`
	CreatedAt  time.Time          `bson:"created_at"`
}

// Обновляем структуру SMSCode, добавляя поле ID
type SMSCode struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	Phone     string             `bson:"phone"`
	Code      string             `bson:"code"`
	CreatedAt time.Time          `bson:"created_at"`
	Used      bool               `bson:"used"`
}

// Обновляем структуру CartItem - убираем поле Currency
type CartItem struct {
	ProductID primitive.ObjectID `bson:"product_id" json:"productId"`
	Name      string             `bson:"name" json:"name"`
	Price     float64            `bson:"price" json:"price"`
	Quantity  int                `bson:"quantity" json:"quantity"`
}

type Cart struct {
	ID        primitive.ObjectID `bson:"_id" json:"id"`
	UserID    primitive.ObjectID `bson:"user_id" json:"userId"`
	Items     []CartItem         `bson:"items" json:"items"`
	Total     float64            `bson:"total" json:"total"`
	CreatedAt time.Time          `bson:"created_at" json:"createdAt"`
	UpdatedAt time.Time          `bson:"updated_at" json:"updatedAt"`
}

type Transaction struct {
	ID        primitive.ObjectID `bson:"_id" json:"id"`
	UserID    primitive.ObjectID `bson:"user_id" json:"user_id"`
	CartID    primitive.ObjectID `bson:"cart_id" json:"cart_id"`
	Total     float64            `bson:"total" json:"total"`
	Status    string             `bson:"status" json:"status"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time          `bson:"updated_at" json:"updated_at"`
}

// Структура для запроса добавления в корзину
type AddToCartRequest struct {
	ProductID string `json:"productId"`
	Quantity  int    `json:"quantity"`
}

var (
	client          *mongo.Client
	database        *mongo.Database
	usersCol        *mongo.Collection
	rolesCol        *mongo.Collection
	devicesCol      *mongo.Collection
	smsCodesCol     *mongo.Collection
	cartsCol        *mongo.Collection
	transactionsCol *mongo.Collection
	productsCol     *mongo.Collection
	logger          = logrus.New()
	limiter         = rate.NewLimiter(rate.Every(1*time.Second), 1)
	jwtSecret       = []byte("your-secret-key")
)

// Инициализация логирования
func init() {
	// Устанавливаем формат логов
	logger.SetFormatter(&logrus.JSONFormatter{})
	// Выводим логи в стандартный вывод
	logger.SetOutput(os.Stdout)
	// Уровень логирования
	logger.SetLevel(logrus.InfoLevel)
	// Загружаем переменные окружения из .env файла
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found")
	}
}

// Инициализация базы данных
func initDB() {
	ctx := context.Background()

	// Подключение к MongoDB
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	var err error
	client, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		logger.WithError(err).Fatal("Failed to connect to MongoDB")
	}

	// Проверка подключения
	err = client.Ping(ctx, nil)
	if err != nil {
		logger.WithError(err).Fatal("Failed to ping MongoDB")
	}

	// Инициализация базы данных и коллекций
	database = client.Database("advprog")
	usersCol = database.Collection("users")
	rolesCol = database.Collection("roles")
	devicesCol = database.Collection("devices")
	smsCodesCol = database.Collection("sms_codes")
	cartsCol = database.Collection("carts")
	transactionsCol = database.Collection("transactions")

	// Создание индексов
	_, err = usersCol.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		logger.WithError(err).Fatal("Failed to create email index")
	}

	// Инициализируем роли и разрешения
	initializeRolesAndPermissions()

	// Инициализируем устройства
	initializeDevices()

	logger.Info("MongoDB connected and initialized successfully")
}

// Обработка ошибок
func handleError(w http.ResponseWriter, err error, message string, statusCode int) {
	logger.WithFields(logrus.Fields{
		"error": err,
	}).Error(message)
	http.Error(w, message, statusCode)
}

// Исправляем функцию supportHandler
func supportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Загружаем HTML-шаблон для формы поддержки
		tmpl, err := template.ParseFiles("./public/support.html")
		if err != nil {
			handleError(w, err, "Failed to load template", http.StatusInternalServerError)
			return
		}
		if err := tmpl.Execute(w, nil); err != nil {
			handleError(w, err, "Failed to render template", http.StatusInternalServerError)
			return
		}
		return
	}

	if r.Method == http.MethodPost {
		// Парсим форму
		r.ParseMultipartForm(10 << 20) // Ограничение: 10 MB

		userEmail := r.FormValue("email")
		subject := r.FormValue("subject")
		message := r.FormValue("message")

		// Проверяем обязательные поля
		if userEmail == "" || subject == "" || message == "" {
			http.Error(w, "All fields (email, subject, message) are required", http.StatusBadRequest)
			return
		}

		// Работа с файлом
		var attachmentPath string
		file, header, err := r.FormFile("attachment")
		if err == nil && file != nil {
			defer file.Close()
			attachmentPath = "./uploads/" + header.Filename
			out, err := os.Create(attachmentPath)
			if err != nil {
				handleError(w, err, "Failed to save attachment", http.StatusInternalServerError)
				return
			}
			defer out.Close()
			if _, err := io.Copy(out, file); err != nil {
				handleError(w, err, "Failed to save attachment", http.StatusInternalServerError)
				return
			}
		}

		// Исправляем сохранение сообщения в MongoDB
		supportMessage := SupportMessage{
			ID:         primitive.NewObjectID(),
			UserEmail:  userEmail,
			Subject:    subject,
			Message:    message,
			Attachment: attachmentPath,
			CreatedAt:  time.Now(),
		}

		if _, err := database.Collection("support_messages").InsertOne(context.Background(), supportMessage); err != nil {
			handleError(w, err, "Failed to save support message", http.StatusInternalServerError)
			return
		}

		// Отправляем email
		err = sendEmail(EmailData{
			To:      userEmail,
			Subject: subject,
			Body:    message,
		})
		if err != nil {
			handleError(w, err, "Failed to send email", http.StatusInternalServerError)
			return
		}

		// Перенаправление на страницу с успешным уведомлением
		http.Redirect(w, r, "/support?success=1", http.StatusSeeOther)
	}
}

// Конфигурация SMTP
const (
	smtpHost       = "smtp.gmail.com"
	smtpPort       = 587
	senderEmail    = "adilhan2040@gmail.com"
	senderPassword = "cnidyxyehqdnbqlp"
)

// EmailData структура для отправки email
type EmailData struct {
	To      string
	Subject string
	Body    string
}

// Изменяем функцию sendEmail
func sendEmail(data EmailData) error {
	m := gomail.NewMessage()
	m.SetHeader("From", senderEmail)
	m.SetHeader("To", data.To)
	m.SetHeader("Subject", data.Subject)
	m.SetBody("text/html", data.Body)

	d := gomail.NewDialer(smtpHost, smtpPort, senderEmail, senderPassword)

	if err := d.DialAndSend(m); err != nil {
		log.Printf("Ошибка отправки email: %v", err)
		return err
	}
	return nil
}

// Отправка верификационного email
func sendVerificationEmail(email, link string) error {
	emailData := EmailData{
		To:      email,
		Subject: "Verify your email address",
		Body: fmt.Sprintf(`
Hello!

Thank you for registering. Please click the link below to verify your email address:

%s

If you didn't register for an account, please ignore this email.

Best regards,
Your Application Team`, link),
	}

	return sendEmail(emailData)
}

// Отправка OTP
func sendOTPEmail(email, otp string) error {
	emailData := EmailData{
		To:      email,
		Subject: "Your Login OTP",
		Body: fmt.Sprintf(`
Hello!

Your one-time password (OTP) for login is: %s

This OTP will expire in 5 minutes.

If you didn't request this OTP, please ignore this email.

Best regards,
Your Application Team`, otp),
	}

	return sendEmail(emailData)
}

func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// Исправляем функцию productsHandler
func productsHandler(w http.ResponseWriter, r *http.Request) {
	// Устанавливаем заголовки CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	// Обрабатываем preflight запрос
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Проверяем метод
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Получаем параметры фильтрации
	catalog := r.URL.Query().Get("catalog")
	minPriceStr := r.URL.Query().Get("minPrice")
	maxPriceStr := r.URL.Query().Get("maxPrice")
	sortBy := r.URL.Query().Get("sortBy")
	sortOrder := r.URL.Query().Get("sortOrder")

	// Создаем фильтр
	filter := bson.M{}
	if catalog != "" && catalog != "All" {
		filter["catalog"] = catalog
	}

	// Добавляем фильтр по цене
	if minPriceStr != "" || maxPriceStr != "" {
		priceFilter := bson.M{}
		if minPriceStr != "" {
			minPrice, err := strconv.ParseFloat(minPriceStr, 64)
			if err == nil {
				priceFilter["$gte"] = minPrice
			}
		}
		if maxPriceStr != "" {
			maxPrice, err := strconv.ParseFloat(maxPriceStr, 64)
			if err == nil {
				priceFilter["$lte"] = maxPrice
			}
		}
		if len(priceFilter) > 0 {
			filter["price"] = priceFilter
		}
	}

	// Создаем опции сортировки
	opts := options.Find()
	if sortBy != "" && sortBy != "none" {
		sortDirection := 1
		if sortOrder == "desc" {
			sortDirection = -1
		}
		opts.SetSort(bson.D{{Key: sortBy, Value: sortDirection}})
	}

	// Получаем продукты из базы данных
	cursor, err := devicesCol.Find(context.Background(), filter, opts)
	if err != nil {
		logger.WithError(err).Error("Failed to fetch products")
		http.Error(w, `{"error":"Failed to fetch products"}`, http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.Background())

	var products []Device
	if err = cursor.All(context.Background(), &products); err != nil {
		logger.WithError(err).Error("Failed to decode products")
		http.Error(w, `{"error":"Failed to decode products"}`, http.StatusInternalServerError)
		return
	}

	// Добавляем логирование для отладки
	for _, product := range products {
		logger.WithFields(logrus.Fields{
			"id":   product.ID.Hex(),
			"name": product.Name,
		}).Info("Sending product")
	}

	// Возвращаем результат
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(products); err != nil {
		logger.WithError(err).Error("Failed to encode response")
		http.Error(w, `{"error":"Failed to encode response"}`, http.StatusInternalServerError)
		return
	}
}

// Мягкое завершение работы
func gracefulShutdown(srv *http.Server) {
	// Канал для получения сигнала завершения
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	// Ожидание сигнала
	<-stop

	logger.Info("Shutting down server...")

	// Устанавливаем тайм-аут на завершение работы
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.WithError(err).Fatal("Server shutdown failed")
	}
	logger.Info("Server gracefully stopped")
}

// Обработчик регистрации
func registerHandler(w http.ResponseWriter, r *http.Request) {
	// Настраиваем CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	// Предварительный запрос OPTIONS
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Проверяем метод
	if r.Method != "POST" {
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Читаем тело запроса
	var user struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		log.Printf("Ошибка при декодировании JSON: %v", err)
		http.Error(w, `{"error":"Invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Проверяем данные
	if user.Email == "" || user.Password == "" {
		http.Error(w, `{"error":"Email and password are required"}`, http.StatusBadRequest)
		return
	}

	// Хешируем пароль
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Ошибка при хешировании пароля: %v", err)
		http.Error(w, `{"error":"Internal server error"}`, http.StatusInternalServerError)
		return
	}

	// Создаем ID для нового пользователя
	userID := primitive.NewObjectID()

	// Создаем пользователя в базе данных
	_, err = client.Database("ass4").Collection("users").InsertOne(context.Background(), bson.M{
		"_id":      userID,
		"email":    user.Email,
		"password": string(hashedPassword),
		"roles":    []string{"user"},
	})

	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			http.Error(w, `{"error":"Email already exists"}`, http.StatusConflict)
			return
		}
		log.Printf("Ошибка при создании пользователя: %v", err)
		http.Error(w, `{"error":"Failed to create user"}`, http.StatusInternalServerError)
		return
	}

	// Отправляем успешный ответ
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User registered successfully",
	})

	verificationToken := generateToken() // Используем существующую функцию generateToken

	verificationLink := fmt.Sprintf("http://localhost:8080/verify?token=%s&email=%s",
		verificationToken, user.Email)
	emailBody := fmt.Sprintf(`
		<h2>Welcome to our service!</h2>
		<p>Please click the link below to verify your email:</p>
		<a href="%s">Verify Email</a>
	`, verificationLink)

	// Сохраняем токен верификации в базе данных
	_, err = usersCol.UpdateOne(
		context.Background(),
		bson.M{"_id": userID}, // Используем созданный userID
		bson.M{"$set": bson.M{"email_verify_token": verificationToken}},
	)
	if err != nil {
		log.Printf("Ошибка сохранения токена верификации: %v", err)
		return
	}

	// Отправляем email
	if err := sendEmail(EmailData{
		To:      user.Email,
		Subject: "Verify Your Email",
		Body:    emailBody,
	}); err != nil {
		log.Printf("Ошибка отправки верификационного email: %v", err)
	}
}

// Генерация OTP
func generateOTP() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%06d", rand.Intn(1000000))
}

// Обработчик верификации email
func verifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Invalid verification token", http.StatusBadRequest)
		return
	}

	// Ищем пользователя по токену верификации
	var user User
	err := usersCol.FindOne(context.Background(), bson.M{"email_verify_token": token}).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid verification token", http.StatusBadRequest)
		return
	}

	// Получаем роль пользователя
	var userRole Role
	err = rolesCol.FindOne(context.Background(), bson.M{"name": "user"}).Decode(&userRole)
	if err != nil {
		http.Error(w, "Failed to get user role", http.StatusInternalServerError)
		return
	}

	// Обновляем пользователя
	_, err = usersCol.UpdateOne(
		context.Background(),
		bson.M{"_id": user.ID},
		bson.M{
			"$set": bson.M{
				"is_email_verified": true,
				"role_ids":          []primitive.ObjectID{userRole.ID},
			},
			"$unset": bson.M{
				"email_verify_token": "",
			},
		},
	)
	if err != nil {
		http.Error(w, "Failed to verify email", http.StatusInternalServerError)
		return
	}

	// Перенаправляем на страницу входа
	http.Redirect(w, r, "/login.html", http.StatusSeeOther)
}

// Добавьте новый обработчик для оформления заказа
func checkoutHandler(w http.ResponseWriter, r *http.Request) {
	// Добавляем CORS заголовки
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	// Обрабатываем preflight запрос
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Получаем ID пользователя из токена
	userID, err := getUserIDFromToken(r)
	if err != nil {
		log.Printf("Auth error: %v", err) // Добавляем логирование
		http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Получаем корзину пользователя
	var cart Cart
	err = cartsCol.FindOne(context.Background(), bson.M{"user_id": userID}).Decode(&cart)
	if err != nil {
		log.Printf("Cart error: %v", err) // Добавляем логирование
		http.Error(w, `{"error": "Cart not found"}`, http.StatusNotFound)
		return
	}

	// Создаем новую транзакцию
	transaction := Transaction{
		ID:        primitive.NewObjectID(),
		UserID:    userID,
		CartID:    cart.ID,
		Total:     cart.Total,
		Status:    "pending",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_, err = transactionsCol.InsertOne(context.Background(), transaction)
	if err != nil {
		log.Printf("Transaction error: %v", err) // Добавляем логирование
		http.Error(w, `{"error": "Failed to create transaction"}`, http.StatusInternalServerError)
		return
	}

	// Отправляем ответ
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"transactionId": transaction.ID.Hex(),
	})
}

// В функции main добавьте новые маршруты

// Обработчик входа
func loginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var loginData struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
		http.Error(w, `{"error":"Invalid request format"}`, http.StatusBadRequest)
		return
	}

	var user User
	err := usersCol.FindOne(context.Background(), bson.M{"email": loginData.Email}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, `{"error":"User not found"}`, http.StatusUnauthorized)
		} else {
			http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
		}
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password)); err != nil {
		http.Error(w, `{"error":"Invalid password"}`, http.StatusUnauthorized)
		return
	}

	// Создаем JWT токен с user_id
	claims := jwt.MapClaims{
		"user_id": user.ID.Hex(),
		"email":   user.Email,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		http.Error(w, `{"error":"Failed to create token"}`, http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"token":   tokenString,
		"user_id": user.ID.Hex(),
		"email":   user.Email,
	}

	json.NewEncoder(w).Encode(response)
}

func getUserIDFromToken(r *http.Request) (primitive.ObjectID, error) {
	logger := logrus.WithField("func", "getUserIDFromToken")

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return primitive.ObjectID{}, fmt.Errorf("no auth header")
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		return primitive.ObjectID{}, fmt.Errorf("invalid token format")
	}

	logger.Infof("Token string: %s", tokenString)

	// Парсим токен
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil {
		logger.WithError(err).Error("Failed to parse token")
		return primitive.ObjectID{}, fmt.Errorf("invalid token: %v", err)
	}

	if !token.Valid {
		return primitive.ObjectID{}, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		logger.Error("Failed to get claims")
		return primitive.ObjectID{}, fmt.Errorf("invalid token claims")
	}

	// Получаем email из claims
	email, ok := claims["email"].(string)
	if !ok {
		logger.Error("Email not found in claims")
		return primitive.ObjectID{}, fmt.Errorf("email not found in token")
	}

	// Ищем пользователя по email
	var user User
	err = usersCol.FindOne(context.Background(), bson.M{"email": email}).Decode(&user)
	if err != nil {
		logger.WithError(err).Error("Failed to find user")
		return primitive.ObjectID{}, fmt.Errorf("user not found")
	}

	return user.ID, nil
}

// Вспомогательные функции
func generateToken() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return fmt.Sprintf("%x", b)
}

// Обработчик проверки OTP
func verifyOTPHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var verifyData struct {
		TempToken string `json:"tempToken"`
		OTP       string `json:"otp"`
	}

	if err := json.NewDecoder(r.Body).Decode(&verifyData); err != nil {
		logger.WithError(err).Error("Failed to decode request body")
		http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Ищем пользователя по временному токену
	var user User
	err := usersCol.FindOne(context.Background(), bson.M{
		"temp_token":     verifyData.TempToken,
		"otp_expires_at": bson.M{"$gt": time.Now()},
	}).Decode(&user)

	if err != nil {
		logger.WithError(err).Error("User not found or OTP expired")
		http.Error(w, `{"error": "Invalid or expired OTP"}`, http.StatusUnauthorized)
		return
	}

	// Проверяем OTP
	if user.OTP != verifyData.OTP {
		logger.Error("Invalid OTP provided")
		http.Error(w, `{"error": "Invalid OTP"}`, http.StatusUnauthorized)
		return
	}

	// Генерируем JWT токен
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = user.ID.Hex()
	claims["email"] = user.Email
	claims["exp"] = time.Now().Add(24 * time.Hour).Unix()

	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		logger.WithError(err).Error("Failed to generate JWT token")
		http.Error(w, `{"error": "Failed to generate token"}`, http.StatusInternalServerError)
		return
	}

	// Очищаем OTP и временный токен
	_, err = usersCol.UpdateOne(
		context.Background(),
		bson.M{"_id": user.ID},
		bson.M{
			"$set": bson.M{
				"otp":            "",
				"temp_token":     "",
				"otp_expires_at": time.Time{},
			},
		},
	)

	if err != nil {
		logger.WithError(err).Error("Failed to clear OTP data")
		// Продолжаем выполнение, так как токен уже сгенерирован
	}

	// Отправляем успешный ответ
	response := map[string]string{
		"token":   tokenString,
		"message": "Login successful",
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.WithError(err).Error("Failed to encode response")
		http.Error(w, `{"error": "Failed to encode response"}`, http.StatusInternalServerError)
		return
	}

	logger.Infof("OTP verified successfully for user: %s", user.Email)
}

// Вспомогательная функция для получения имен ролей
func getRoleNames(roles []Role) []string {
	names := make([]string, len(roles))
	for i, role := range roles {
		names[i] = role.Name
	}
	return names
}

// Функция для генерации SMS кода
func generateSMSCode() string {
	return fmt.Sprintf("%06d", rand.Intn(999999))
}

// Функция для отправки SMS (здесь нужно будет интегрировать реального SMS провайдера)
func sendSMS(phone, code string) error {
	// В реальном приложении здесь будет код для отправки SMS
	// Например, через Twilio или другого провайдера
	log.Printf("Отправка SMS на номер %s с кодом: %s", phone, code)
	return nil
}

// Обновляем функцию handleSendSMS
func handleSendSMS(w http.ResponseWriter, r *http.Request) {
	phone := r.FormValue("phone")
	if phone == "" {
		http.Error(w, "Номер телефона обязателен", http.StatusBadRequest)
		return
	}

	code := generateSMSCode()
	smsCode := SMSCode{
		ID:        primitive.NewObjectID(),
		Phone:     phone,
		Code:      code,
		CreatedAt: time.Now(),
		Used:      false,
	}

	// Сохраняем код в MongoDB
	_, err := smsCodesCol.InsertOne(context.Background(), smsCode)
	if err != nil {
		handleError(w, err, "Failed to save SMS code", http.StatusInternalServerError)
		return
	}

	if err := sendSMS(phone, code); err != nil {
		http.Error(w, "Ошибка отправки SMS", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// Обновляем функцию handleVerifySMS
func handleVerifySMS(w http.ResponseWriter, r *http.Request) {
	phone := r.FormValue("phone")
	code := r.FormValue("code")

	var smsCode SMSCode
	err := smsCodesCol.FindOne(
		context.Background(),
		bson.M{
			"phone": phone,
			"code":  code,
			"used":  false,
			"created_at": bson.M{
				"$gt": time.Now().Add(-5 * time.Minute),
			},
		},
	).Decode(&smsCode)

	if err != nil {
		http.Error(w, "Неверный код или код истек", http.StatusBadRequest)
		return
	}

	// Помечаем код как использованный
	_, err = smsCodesCol.UpdateOne(
		context.Background(),
		bson.M{"_id": smsCode.ID},
		bson.M{"$set": bson.M{"used": true}},
	)
	if err != nil {
		handleError(w, err, "Failed to update SMS code", http.StatusInternalServerError)
		return
	}

	// Создаем JWT токен
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"phone": phone,
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Ошибка создания токена", http.StatusInternalServerError)
		return
	}

	// Отправляем токен клиенту
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

// Структура для JWT claims
type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	jwt.StandardClaims
}

// Функция для проверки JWT токена
func validateToken(tokenString string) (*Claims, error) {
	// Проверяем, что токен не пустой
	if tokenString == "" {
		return nil, errors.New("empty token")
	}

	// Создаем новый claims
	claims := &Claims{}

	// Парсим токен
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Проверяем метод подписи
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Возвращаем секретный ключ для проверки подписи
		return []byte(jwtSecret), nil
	})

	// Проверяем ошибки парсинга
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, errors.New("invalid token signature")
		}
		return nil, err
	}

	// Проверяем валидность токена
	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Проверяем срок действия токена
	if claims.ExpiresAt < time.Now().Unix() {
		return nil, errors.New("token expired")
	}

	return claims, nil
}

// Middleware для проверки JWT токена
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Получаем токен из заголовка
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Убираем префикс "Bearer "
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Проверяем токен
		claims, err := validateToken(tokenString)
		if err != nil {
			logger.WithError(err).Error("Invalid token")
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Добавляем claims в контекст запроса
		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// Middleware для проверки разрешений
func permissionMiddleware(permission string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
			// Получаем claims из контекста
			claims := r.Context().Value("claims").(*Claims)

			// Получаем пользователя из базы
			userID, err := primitive.ObjectIDFromHex(claims.UserID)
			if err != nil {
				logger.WithError(err).Error("Invalid user ID in token")
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			var user User
			err = usersCol.FindOne(r.Context(), bson.M{"_id": userID}).Decode(&user)
			if err != nil {
				logger.WithError(err).Error("Failed to fetch user")
				http.Error(w, "User not found", http.StatusUnauthorized)
				return
			}

			// Проверяем наличие разрешения
			hasPermission := false
			for _, roleID := range user.RoleIDs {
				var role Role
				err := rolesCol.FindOne(r.Context(), bson.M{"_id": roleID}).Decode(&role)
				if err != nil {
					logger.WithError(err).Error("Failed to fetch role")
					http.Error(w, "Failed to fetch role", http.StatusInternalServerError)
					return
				}
				for _, perm := range role.Permissions {
					if perm.Name == permission {
						hasPermission = true
						break
					}
				}
				if hasPermission {
					break
				}
			}

			if !hasPermission {
				logger.WithFields(logrus.Fields{
					"user_id":    userID.Hex(),
					"permission": permission,
				}).Error("Permission denied")
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// Обработчик для получения списка ролей
func listRolesHandler(w http.ResponseWriter, r *http.Request) {
	var roles []Role
	cursor, err := rolesCol.Find(context.Background(), bson.M{})
	if err != nil {
		handleError(w, err, "Failed to fetch roles", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.Background())

	if err = cursor.All(context.Background(), &roles); err != nil {
		handleError(w, err, "Failed to decode roles", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(roles)
}

// Добавляем обработчик для получения списка разрешений
func listPermissionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Получаем все разрешения из базы
	cursor, err := database.Collection("permissions").Find(context.Background(), bson.M{})
	if err != nil {
		handleError(w, err, "Failed to fetch permissions", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.Background())

	var permissions []Permission
	if err = cursor.All(context.Background(), &permissions); err != nil {
		handleError(w, err, "Failed to decode permissions", http.StatusInternalServerError)
		return
	}

	// Если разрешений нет, создаем базовые
	if len(permissions) == 0 {
		permissions = []Permission{
			{
				ID:          primitive.NewObjectID(),
				Name:        "manage_roles",
				Description: "Can manage roles and permissions",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
			{
				ID:          primitive.NewObjectID(),
				Name:        "view_products",
				Description: "Can view products",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
			{
				ID:          primitive.NewObjectID(),
				Name:        "manage_products",
				Description: "Can manage products",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
			{
				ID:          primitive.NewObjectID(),
				Name:        "manage_users",
				Description: "Can manage users",
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			},
		}

		// Сохраняем базовые разрешения
		for _, perm := range permissions {
			_, err := database.Collection("permissions").InsertOne(context.Background(), perm)
			if err != nil {
				logger.WithError(err).Error("Failed to create permission")
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(permissions)
}

// Обработчик для добавления новой роли
func addRoleHandler(w http.ResponseWriter, r *http.Request) {
	// Проверяем метод
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Проверяем токен
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Убираем префикс "Bearer "
	token = strings.TrimPrefix(token, "Bearer ")

	// Проверяем токен и получаем claims
	claims, err := validateToken(token)
	if err != nil {
		logger.WithError(err).Error("Invalid token")
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Проверяем права доступа
	userID, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		logger.WithError(err).Error("Invalid user ID in token")
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Получаем пользователя из базы
	var user User
	err = usersCol.FindOne(context.Background(), bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		logger.WithError(err).Error("Failed to fetch user")
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	// Проверяем наличие разрешения manage_roles
	hasPermission := false
	for _, roleID := range user.RoleIDs {
		var role Role
		err := rolesCol.FindOne(context.Background(), bson.M{"_id": roleID}).Decode(&role)
		if err != nil {
			logger.WithError(err).Error("Failed to fetch role")
			http.Error(w, "Failed to fetch role", http.StatusInternalServerError)
			return
		}
		for _, perm := range role.Permissions {
			if perm.Name == "manage_roles" {
				hasPermission = true
				break
			}
		}
		if hasPermission {
			break
		}
	}

	if !hasPermission {
		logger.Error("User doesn't have manage_roles permission")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Декодируем данные роли
	var roleData struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}

	if err := json.NewDecoder(r.Body).Decode(&roleData); err != nil {
		logger.WithError(err).Error("Invalid request data")
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		return
	}

	// Проверяем обязательные поля
	if roleData.Name == "" {
		http.Error(w, "Role name is required", http.StatusBadRequest)
		return
	}

	var permissions []Permission

	// Проверяем, есть ли выбранные разрешения
	if len(roleData.Permissions) > 0 {
		var permissionIDs []primitive.ObjectID
		for _, permID := range roleData.Permissions {
			objID, err := primitive.ObjectIDFromHex(permID)
			if err != nil {
				logger.WithError(err).Error("Invalid permission ID")
				http.Error(w, "Invalid permission ID", http.StatusBadRequest)
				return
			}
			permissionIDs = append(permissionIDs, objID)
		}

		cursor, err := database.Collection("permissions").Find(
			context.Background(),
			bson.M{"_id": bson.M{"$in": permissionIDs}},
		)
		if err != nil {
			logger.WithError(err).Error("Failed to fetch permissions")
			handleError(w, err, "Failed to fetch permissions", http.StatusInternalServerError)
			return
		}
		defer cursor.Close(context.Background())

		if err = cursor.All(context.Background(), &permissions); err != nil {
			logger.WithError(err).Error("Failed to decode permissions")
			handleError(w, err, "Failed to decode permissions", http.StatusInternalServerError)
			return
		}
	}

	// Создаем новую роль
	newRole := Role{
		ID:          primitive.NewObjectID(),
		Name:        roleData.Name,
		Description: roleData.Description,
		Permissions: permissions,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Сохраняем роль
	_, err = rolesCol.InsertOne(context.Background(), newRole)
	if err != nil {
		logger.WithError(err).Error("Failed to create role")
		handleError(w, err, "Failed to create role", http.StatusInternalServerError)
		return
	}

	// Логируем успешное создание роли
	logger.WithFields(logrus.Fields{
		"role_id":   newRole.ID.Hex(),
		"role_name": newRole.Name,
		"user_id":   userID.Hex(),
	}).Info("Role created successfully")

	// Возвращаем ответ
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Role created successfully",
		"role":    newRole,
	})
}

// Обработчик для получения информации о конкретной роли
func getRoleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Получаем ID роли из параметров запроса
	roleID := r.URL.Query().Get("id")
	if roleID == "" {
		http.Error(w, "Role ID is required", http.StatusBadRequest)
		return
	}

	// Преобразуем строковый ID в ObjectID
	objID, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		http.Error(w, "Invalid role ID", http.StatusBadRequest)
		return
	}

	// Получаем роль из базы данных
	var role Role
	err = rolesCol.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&role)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Role not found", http.StatusNotFound)
			return
		}
		handleError(w, err, "Failed to fetch role", http.StatusInternalServerError)
		return
	}

	// Отправляем данные о роли
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(role)
}

// Обработчик для удаления роли
func deleteRoleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	roleID := r.URL.Query().Get("id")
	if roleID == "" {
		http.Error(w, "Role ID is required", http.StatusBadRequest)
		return
	}

	objID, err := primitive.ObjectIDFromHex(roleID)
	if err != nil {
		http.Error(w, "Invalid role ID", http.StatusBadRequest)
		return
	}

	// Проверяем, не пытаемся ли удалить роль admin
	var role Role
	err = rolesCol.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&role)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Role not found", http.StatusNotFound)
			return
		}
		handleError(w, err, "Failed to fetch role", http.StatusInternalServerError)
		return
	}

	if role.Name == "admin" {
		http.Error(w, "Cannot delete admin role", http.StatusForbidden)
		return
	}

	// Удаляем роль
	result, err := rolesCol.DeleteOne(context.Background(), bson.M{"_id": objID})
	if err != nil {
		handleError(w, err, "Failed to delete role", http.StatusInternalServerError)
		return
	}

	if result.DeletedCount == 0 {
		http.Error(w, "Role not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// Обработчик для обновления роли
func updateRoleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var roleData struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}

	if err := json.NewDecoder(r.Body).Decode(&roleData); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		return
	}

	// Проверяем ID роли
	roleID, err := primitive.ObjectIDFromHex(roleData.ID)
	if err != nil {
		http.Error(w, "Invalid role ID", http.StatusBadRequest)
		return
	}

	// Проверяем существование роли
	var existingRole Role
	err = rolesCol.FindOne(context.Background(), bson.M{"_id": roleID}).Decode(&existingRole)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.Error(w, "Role not found", http.StatusNotFound)
			return
		}
		handleError(w, err, "Failed to fetch role", http.StatusInternalServerError)
		return
	}

	// Если это роль admin, проверяем, не пытаемся ли изменить её имя
	if existingRole.Name == "admin" && roleData.Name != "admin" {
		http.Error(w, "Cannot change admin role name", http.StatusForbidden)
		return
	}

	// Получаем разрешения
	var permissionIDs []primitive.ObjectID
	for _, permID := range roleData.Permissions {
		objID, err := primitive.ObjectIDFromHex(permID)
		if err != nil {
			http.Error(w, "Invalid permission ID", http.StatusBadRequest)
			return
		}
		permissionIDs = append(permissionIDs, objID)
	}

	// Получаем разрешения из базы данных
	cursor, err := database.Collection("permissions").Find(
		context.Background(),
		bson.M{"_id": bson.M{"$in": permissionIDs}},
	)
	if err != nil {
		handleError(w, err, "Failed to fetch permissions", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.Background())

	var permissions []Permission
	if err = cursor.All(context.Background(), &permissions); err != nil {
		handleError(w, err, "Failed to decode permissions", http.StatusInternalServerError)
		return
	}

	// Обновляем роль
	update := bson.M{
		"$set": bson.M{
			"name":        roleData.Name,
			"description": roleData.Description,
			"permissions": permissions,
			"updated_at":  time.Now(),
		},
	}

	result, err := rolesCol.UpdateOne(
		context.Background(),
		bson.M{"_id": roleID},
		update,
	)

	if err != nil {
		handleError(w, err, "Failed to update role", http.StatusInternalServerError)
		return
	}

	if result.MatchedCount == 0 {
		http.Error(w, "Role not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// Функция для инициализации устройств
func initializeDevices() {
	devices := []Device{
		{
			ID:      primitive.NewObjectID(),
			Name:    "Смартфон",
			Price:   999.99,
			Catalog: "Электроника",
		},
		// ... другие устройства ...
	}

	// Очищаем коллекцию перед добавлением
	devicesCol.DeleteMany(context.Background(), bson.M{})

	for _, device := range devices {
		_, err := devicesCol.InsertOne(context.Background(), device)
		if err != nil {
			log.Printf("Error inserting device: %v", err)
		}
	}
}

// Функция для инициализации ролей и разрешений
func initializeRolesAndPermissions() {
	ctx := context.Background()

	// Базовые разрешения
	permissions := []Permission{
		{
			ID:          primitive.NewObjectID(),
			Name:        "manage_roles",
			Description: "Can manage roles and permissions",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          primitive.NewObjectID(),
			Name:        "view_products",
			Description: "Can view products",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          primitive.NewObjectID(),
			Name:        "manage_products",
			Description: "Can manage products",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          primitive.NewObjectID(),
			Name:        "manage_users",
			Description: "Can manage users",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	// Проверяем существование разрешений
	permCount, err := database.Collection("permissions").CountDocuments(ctx, bson.M{})
	if err != nil {
		logger.WithError(err).Error("Failed to count permissions")
		return
	}

	// Если разрешений нет, создаем их
	if permCount == 0 {
		for _, perm := range permissions {
			_, err := database.Collection("permissions").InsertOne(ctx, perm)
			if err != nil {
				logger.WithError(err).Error("Failed to create permission")
			}
		}
		logger.Info("Permissions initialized successfully")
	}

	// Проверяем существование роли админа
	roleCount, err := rolesCol.CountDocuments(ctx, bson.M{"name": "admin"})
	if err != nil {
		logger.WithError(err).Error("Failed to count admin role")
		return
	}

	// Если роли админа нет, создаем её
	if roleCount == 0 {
		adminRole := Role{
			ID:          primitive.NewObjectID(),
			Name:        "admin",
			Description: "Administrator role with full access",
			Permissions: permissions,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		_, err = rolesCol.InsertOne(ctx, adminRole)
		if err != nil {
			logger.WithError(err).Error("Failed to create admin role")
			return
		}
		logger.Info("Admin role initialized successfully")
	}
}

// Инициализация тестового пользователя
func initializeTestUser() {
	ctx := context.Background()

	// Проверяем существование тестового пользователя
	var user User
	err := usersCol.FindOne(ctx, bson.M{"email": "test@example.com"}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		// Создаем хеш пароля
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte("test123"), bcrypt.DefaultCost)
		if err != nil {
			logger.WithError(err).Error("Failed to hash password")
			return
		}

		// Создаем тестового пользователя
		testUser := User{
			ID:        primitive.NewObjectID(),
			Email:     "test@example.com",
			Password:  string(hashedPassword),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		_, err = usersCol.InsertOne(ctx, testUser)
		if err != nil {
			logger.WithError(err).Error("Failed to create test user")
			return
		}

		logger.Info("Test user created successfully")
	}
}

// Обработчик для получения продуктов
func getProductsHandler(w http.ResponseWriter, r *http.Request) {
	logger.Info("Getting products") // Добавляем логирование

	// Получаем параметры фильтрации
	catalog := r.URL.Query().Get("catalog")
	minPriceStr := r.URL.Query().Get("minPrice")
	maxPriceStr := r.URL.Query().Get("maxPrice")
	sortBy := r.URL.Query().Get("sortBy")
	sortOrder := r.URL.Query().Get("sortOrder")

	// Создаем фильтр
	filter := bson.M{}
	if catalog != "" && catalog != "All" {
		filter["catalog"] = catalog
	}

	// Добавляем фильтр по цене
	if minPriceStr != "" || maxPriceStr != "" {
		priceFilter := bson.M{}
		if minPriceStr != "" {
			minPrice, err := strconv.ParseFloat(minPriceStr, 64)
			if err == nil {
				priceFilter["$gte"] = minPrice
			}
		}
		if maxPriceStr != "" {
			maxPrice, err := strconv.ParseFloat(maxPriceStr, 64)
			if err == nil {
				priceFilter["$lte"] = maxPrice
			}
		}
		if len(priceFilter) > 0 {
			filter["price"] = priceFilter
		}
	}

	// Создаем опции сортировки
	opts := options.Find()
	if sortBy != "" && sortBy != "none" {
		sortDirection := 1
		if sortOrder == "desc" {
			sortDirection = -1
		}
		opts.SetSort(bson.D{{Key: sortBy, Value: sortDirection}})
	}

	logger.WithField("filter", filter).Info("Applying filter") // Логируем фильтр

	// Получаем продукты из базы данных
	cursor, err := devicesCol.Find(context.Background(), filter, opts)
	if err != nil {
		logger.WithError(err).Error("Failed to fetch products")
		http.Error(w, "Failed to fetch products", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.Background())

	var products []Device
	if err = cursor.All(context.Background(), &products); err != nil {
		logger.WithError(err).Error("Failed to decode products")
		http.Error(w, "Failed to decode products", http.StatusInternalServerError)
		return
	}

	// Добавляем логирование для отладки
	for _, product := range products {
		logger.WithFields(logrus.Fields{
			"id":   product.ID.Hex(),
			"name": product.Name,
		}).Info("Sending product")
	}

	// Возвращаем результат
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(products); err != nil {
		logger.WithError(err).Error("Failed to encode response")
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

// Обработчик для страницы ролей
func rolesPageHandler(w http.ResponseWriter, r *http.Request) {
	// Проверяем метод
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Проверяем авторизацию
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Убираем префикс "Bearer "
	token = strings.TrimPrefix(token, "Bearer ")

	// Проверяем токен
	_, err := validateToken(token)
	if err != nil {
		logger.WithError(err).Error("Invalid token")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Отдаем страницу
	http.ServeFile(w, r, "public/admin/roles.html")
}

// Обработчик удаления пользователя
func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	// Устанавливаем заголовки CORS
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	// Обрабатываем preflight запрос
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodDelete {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Получаем email из параметров запроса
	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, `{"error": "Email is required"}`, http.StatusBadRequest)
		return
	}

	// Удаляем пользователя из базы данных
	result, err := usersCol.DeleteOne(context.Background(), bson.M{"email": email})
	if err != nil {
		logger.WithError(err).Error("Failed to delete user")
		http.Error(w, `{"error": "Failed to delete user"}`, http.StatusInternalServerError)
		return
	}

	if result.DeletedCount == 0 {
		http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
		return
	}

	// Отправляем успешный ответ
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User successfully deleted",
	})
}

// Обработчик выхода из системы
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"error": "Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Проверяем только наличие заголовка Authorization
	if r.Header.Get("Authorization") == "" {
		http.Error(w, `{"error": "No authorization header"}`, http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Successfully logged out",
	})
}

// Структуры данных
type Product struct {
	ID      primitive.ObjectID `bson:"_id" json:"_id"`
	Name    string             `bson:"name" json:"name"`
	Price   float64            `bson:"price" json:"price"`
	Catalog string             `bson:"catalog" json:"catalog"`
}

// Обработчики
func addToCartHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Получаем токен и ID пользователя
	userID, err := getUserIDFromToken(r)
	if err != nil {
		http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var item CartItem
	if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
		http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Находим или создаем корзину пользователя
	var cart Cart
	err = cartsCol.FindOne(context.Background(), bson.M{"user_id": userID}).Decode(&cart)
	if err != nil {
		cart = Cart{
			ID:        primitive.NewObjectID(),
			UserID:    userID,
			Items:     []CartItem{},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
	}

	// Добавляем товар в корзину
	cart.Items = append(cart.Items, item)
	cart.UpdatedAt = time.Now()
	cart.Total = calculateTotal(cart.Items)

	// Сохраняем корзину
	opts := options.Update().SetUpsert(true)
	_, err = cartsCol.UpdateOne(
		context.Background(),
		bson.M{"user_id": userID},
		bson.M{"$set": cart},
		opts,
	)

	if err != nil {
		http.Error(w, `{"error": "Failed to update cart"}`, http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(cart)
}

func createTransactionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	userID, err := getUserIDFromToken(r)
	if err != nil {
		http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Получаем корзину пользователя
	var cart Cart
	err = cartsCol.FindOne(context.Background(), bson.M{"user_id": userID}).Decode(&cart)
	if err != nil {
		http.Error(w, `{"error": "Cart not found"}`, http.StatusNotFound)
		return
	}

	// Создаем транзакцию
	transaction := Transaction{
		ID:        primitive.NewObjectID(),
		UserID:    userID,
		CartID:    cart.ID,
		Total:     cart.Total,
		Status:    "pending",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_, err = transactionsCol.InsertOne(context.Background(), transaction)
	if err != nil {
		http.Error(w, `{"error": "Failed to create transaction"}`, http.StatusInternalServerError)
		return
	}

	// Отправляем запрос в микросервис
	microserviceResp, err := sendToPaymentMicroservice(transaction)
	if err != nil {
		http.Error(w, `{"error": "Payment service unavailable"}`, http.StatusServiceUnavailable)
		return
	}

	json.NewEncoder(w).Encode(microserviceResp)
}

// Вспомогательные функции

func sendToPaymentMicroservice(transaction Transaction) (map[string]interface{}, error) {
	paymentData := map[string]interface{}{
		"transaction_id": transaction.ID.Hex(),
		"amount":         transaction.Total,
		"user_id":        transaction.UserID.Hex(),
	}

	jsonData, err := json.Marshal(paymentData)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post("http://payment-service:8081/process-payment",
		"application/json",
		bytes.NewBuffer(jsonData))

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// Обработчик для получения корзины
func cartHandler(w http.ResponseWriter, r *http.Request) {
	logger := logrus.WithFields(logrus.Fields{
		"handler": "cartHandler",
		"method":  r.Method,
		"path":    r.URL.Path,
	})

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Проверка метода запроса
	if r.Method != "GET" && r.Method != "POST" && r.Method != "DELETE" {
		logger.Warn("Method not allowed")
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Получаем ID пользователя из токена
	userID, err := getUserIDFromToken(r)
	if err != nil {
		logger.WithError(err).Error("Failed to get user ID")
		http.Error(w, `{"error":"Unauthorized"}`, http.StatusUnauthorized)
		return
	}

	if r.Method == "DELETE" {
		// Получаем ID продукта из URL
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 3 {
			http.Error(w, `{"error":"Invalid product ID"}`, http.StatusBadRequest)
			return
		}
		productIDStr := parts[len(parts)-1]

		productID, err := primitive.ObjectIDFromHex(productIDStr)
		if err != nil {
			logger.WithError(err).Error("Invalid product ID format")
			http.Error(w, `{"error":"Invalid product ID"}`, http.StatusBadRequest)
			return
		}

		// Находим и обновляем корзину
		update := bson.M{
			"$pull": bson.M{
				"items": bson.M{
					"product_id": productID,
				},
			},
		}

		result, err := cartsCol.UpdateOne(
			context.Background(),
			bson.M{"user_id": userID},
			update,
		)

		if err != nil {
			logger.WithError(err).Error("Failed to remove item from cart")
			http.Error(w, `{"error":"Failed to remove item"}`, http.StatusInternalServerError)
			return
		}

		// Если товар был удален, обновляем общую сумму
		if result.ModifiedCount > 0 {
			var cart Cart
			err = cartsCol.FindOne(context.Background(), bson.M{"user_id": userID}).Decode(&cart)
			if err == nil {
				cart.Total = calculateTotal(cart.Items)
				cart.UpdatedAt = time.Now()

				_, err = cartsCol.UpdateOne(
					context.Background(),
					bson.M{"user_id": userID},
					bson.M{"$set": bson.M{
						"total":      cart.Total,
						"updated_at": cart.UpdatedAt,
					}},
				)

				if err != nil {
					logger.WithError(err).Error("Failed to update cart total")
				}
			}
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Item removed from cart",
		})
		return
	}

	if r.Method == "GET" {
		// Получаем корзину пользователя
		var cart Cart
		err := cartsCol.FindOne(context.Background(), bson.M{"user_id": userID}).Decode(&cart)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				// Если корзина не найдена, возвращаем пустую корзину
				logger.Info("Cart not found, creating empty cart")
				cart = Cart{
					ID:        primitive.NewObjectID(),
					UserID:    userID,
					Items:     []CartItem{},
					Total:     0,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
			} else {
				logger.WithError(err).Error("Failed to find cart")
				http.Error(w, `{"error":"Failed to load cart"}`, http.StatusInternalServerError)
				return
			}
		}

		logger.Info("Successfully retrieved cart")
		json.NewEncoder(w).Encode(cart)
		return
	}

	if r.Method == "POST" {
		// Чтение тела запроса
		var req struct {
			ProductID string `json:"productId"`
			Quantity  int    `json:"quantity"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			logger.WithError(err).Error("Failed to decode request")
			http.Error(w, `{"error":"Invalid request format"}`, http.StatusBadRequest)
			return
		}

		// Проверка количества
		if req.Quantity <= 0 {
			logger.Warn("Invalid quantity")
			http.Error(w, `{"error":"Quantity must be positive"}`, http.StatusBadRequest)
			return
		}

		// Получение информации о продукте
		productID, err := primitive.ObjectIDFromHex(req.ProductID)
		if err != nil {
			logger.WithError(err).Error("Invalid product ID")
			http.Error(w, `{"error":"Invalid product ID"}`, http.StatusBadRequest)
			return
		}

		var product Device
		err = devicesCol.FindOne(context.Background(), bson.M{"_id": productID}).Decode(&product)
		if err != nil {
			logger.WithError(err).Error("Failed to find product")
			http.Error(w, `{"error":"Product not found"}`, http.StatusNotFound)
			return
		}

		// Поиск или создание корзины
		var cart Cart
		err = cartsCol.FindOne(context.Background(), bson.M{"user_id": userID}).Decode(&cart)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				cart = Cart{
					ID:        primitive.NewObjectID(),
					UserID:    userID,
					Items:     []CartItem{},
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
			} else {
				logger.WithError(err).Error("Failed to find cart")
				http.Error(w, `{"error":"Database error"}`, http.StatusInternalServerError)
				return
			}
		}

		// Добавление товара в корзину
		itemFound := false
		for i := range cart.Items {
			if cart.Items[i].ProductID == productID {
				cart.Items[i].Quantity += req.Quantity
				itemFound = true
				break
			}
		}

		if !itemFound {
			cart.Items = append(cart.Items, CartItem{
				ProductID: productID,
				Name:      product.Name,
				Price:     product.Price,
				Quantity:  req.Quantity,
			})
		}

		cart.UpdatedAt = time.Now()
		cart.Total = calculateTotal(cart.Items)

		// Сохранение корзины
		opts := options.Update().SetUpsert(true)
		_, err = cartsCol.UpdateOne(
			context.Background(),
			bson.M{"user_id": userID},
			bson.M{"$set": cart},
			opts,
		)

		if err != nil {
			logger.WithError(err).Error("Failed to update cart")
			http.Error(w, `{"error":"Failed to update cart"}`, http.StatusInternalServerError)
			return
		}

		logger.Info("Successfully updated cart")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "Cart updated successfully",
			"cart":    cart,
		})
		return
	}
}

// Вспомогательная функция для подсчета общей суммы
func calculateTotal(items []CartItem) float64 {
	var total float64
	for _, item := range items {
		total += float64(item.Quantity) * item.Price
	}
	return total
}

// Добавляем функцию проверки подключения к MongoDB
func checkMongoConnection() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := client.Ping(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to ping MongoDB: %v", err)
	}
	return nil
}

// Обработчик для получения информации о текущем пользователе
func getCurrentUserHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Получаем токен из заголовка
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, `{"error": "No authorization header"}`, http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Используем тот же секретный ключ, что и при создании токена
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte("your-secret-key"), nil // Используйте тот же ключ, что и при создании токена
	})

	if err != nil || !token.Valid {
		http.Error(w, `{"error": "Invalid token"}`, http.StatusUnauthorized)
		return
	}

	// Получаем email из claims
	email, ok := claims["email"].(string)
	if !ok {
		http.Error(w, `{"error": "Invalid token claims"}`, http.StatusUnauthorized)
		return
	}

	// Получаем информацию о пользователе по email
	var user User
	err = usersCol.FindOne(context.Background(), bson.M{"email": email}).Decode(&user)
	if err != nil {
		http.Error(w, `{"error": "User not found"}`, http.StatusNotFound)
		return
	}

	// Формируем ответ
	response := map[string]interface{}{
		"email": user.Email,
	}

	json.NewEncoder(w).Encode(response)
}

// Добавьте новый обработчик для проверки аутентификации

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

func main() {
	log.Println("Запуск сервера...")

	// Инициализация логгера
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Логгер инициализирован")

	// Подключение к MongoDB
	ctx := context.Background()
	var err error

	log.Println("Подключение к MongoDB...")
	client, err = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal("Ошибка подключения к MongoDB:", err)
	}
	defer client.Disconnect(ctx)

	// Проверка подключения
	log.Println("Проверка подключения к MongoDB...")
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal("Ошибка при проверке подключения:", err)
	}
	log.Println("Успешное подключение к MongoDB")

	// Инициализация коллекций
	log.Println("Инициализация коллекций...")
	database = client.Database("ass4")
	usersCol = database.Collection("users")
	devicesCol = database.Collection("devices") // Добавляем инициализацию devicesCol
	productsCol = database.Collection("devices")
	cartsCol = database.Collection("carts")
	transactionsCol = database.Collection("transactions")

	// Создание индексов
	log.Println("Создание индексов...")
	_, err = usersCol.Indexes().CreateOne(
		context.Background(),
		mongo.IndexModel{
			Keys:    bson.D{{Key: "email", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	)
	if err != nil {
		log.Fatal("Ошибка создания индекса для email:", err)
	}
	log.Println("Индексы созданы успешно")

	// Настройка маршрутов
	log.Println("Настройка маршрутов...")
	http.HandleFunc("/register", corsMiddleware(registerHandler))
	http.HandleFunc("/login", corsMiddleware(loginHandler))
	http.HandleFunc("/logout", corsMiddleware(logoutHandler))
	http.HandleFunc("/cart", corsMiddleware(authMiddleware(cartHandler)))
	http.HandleFunc("/products", corsMiddleware(productsHandler))
	http.HandleFunc("/current-user", corsMiddleware(authMiddleware(getCurrentUserHandler)))
	http.HandleFunc("/checkout", corsMiddleware(authMiddleware(checkoutHandler)))
	http.Handle("/", http.FileServer(http.Dir("public")))
	log.Println("Маршруты настроены")

	// Запуск сервера
	log.Println("Запуск HTTP сервера на порту 8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal("Ошибка запуска сервера:", err)
	}
}
