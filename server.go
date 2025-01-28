package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
	"gopkg.in/gomail.v2"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"html/template" // Добавьте этот импорт для шаблонов
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
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
	ID          uint   `gorm:"primaryKey"`
	Name        string `gorm:"type:varchar(50);unique;not null"`
	Description string `gorm:"type:text"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Role struct {
	ID          uint         `gorm:"primaryKey"`
	Name        string       `gorm:"type:varchar(50);unique;not null"`
	Description string       `gorm:"type:text"`
	Permissions []Permission `gorm:"many2many:role_permissions;"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Обновляем структуру User, добавляя поле Roles
type User struct {
	gorm.Model
	Email             string `gorm:"unique"`
	PasswordHash      string
	VerificationToken string // Добавляем поле для токена верификации
	IsVerified        bool
	OTP               string
	OTPExpiresAt      time.Time
	Roles             []Role `gorm:"many2many:user_roles;"`
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

// Структура для данных о товаре
type Device struct {
	ID      uint    `gorm:"primaryKey"`
	Name    string  `gorm:"type:varchar(100)"`
	Price   float64 `gorm:"type:decimal(10,2)"`
	Catalog string  `gorm:"type:varchar(50)"`
}

type SupportMessage struct {
	ID         uint      `gorm:"primaryKey"`
	UserEmail  string    `gorm:"type:varchar(100);not null"`
	Subject    string    `gorm:"type:varchar(255);not null"`
	Message    string    `gorm:"type:text;not null"`
	Attachment string    `gorm:"type:varchar(255)"`
	CreatedAt  time.Time `gorm:"autoCreateTime"`
}

type SMSCode struct {
	Phone     string
	Code      string
	CreatedAt time.Time
	Used      bool
}

var (
	db              *gorm.DB
	logger          = logrus.New()
	limiter         = rate.NewLimiter(rate.Every(1*time.Second), 1) // Лимит 5 запросов в секунду для всех
	clientLimiter   = make(map[string]*rate.Limiter)
	mu              sync.Mutex
	smsCodesStorage = make(map[string]SMSCode)
	jwtSecret       = []byte("your-secret-key") // В продакшене используйте безопасный ключ
)

// Инициализация логирования
func init() {
	// Устанавливаем формат логов
	logger.SetFormatter(&logrus.JSONFormatter{})
	// Выводим логи в стандартный вывод
	logger.SetOutput(os.Stdout)
	// Уровень логирования
	logger.SetLevel(logrus.InfoLevel)
}

// Добавим новую функцию для ожидания подключения к БД
func waitForDB(dsn string) error {
	var err error
	for i := 0; i < 30; i++ { // Пробуем 30 раз
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err == nil {
			return nil
		}
		logger.WithError(err).Info("Waiting for database connection...")
		time.Sleep(2 * time.Second)
	}
	return err
}

// Обновляем функцию initDB для работы с SSL
func initDB() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		logger.Fatal("DATABASE_URL environment variable is not set")
		return
	}

	// Если строка начинается с postgres://, преобразуем её в формат DSN
	if strings.HasPrefix(dsn, "postgres://") {
		pgURL, err := url.Parse(dsn)
		if err != nil {
			logger.WithError(err).Fatal("Failed to parse database URL")
		}

		password, _ := pgURL.User.Password()
		dsn = fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=require",
			pgURL.Hostname(),
			pgURL.Port(),
			pgURL.User.Username(),
			password,
			strings.TrimPrefix(pgURL.Path, "/"),
		)
	}

	// Ждем подключения к базе данных
	if err := waitForDB(dsn); err != nil {
		logger.WithFields(logrus.Fields{
			"dsn": dsn,
		}).Fatal("Failed to connect to database after multiple retries")
	}

	logger.Info("Database connected successfully")

	// Выполняем миграции
	if err := db.AutoMigrate(&User{}, &Device{}, &Role{}, &Permission{}, &SupportMessage{}); err != nil {
		logger.Fatal("Database migration failed: ", err)
	}

	// Создаем базовые роли и разрешения
	createDefaultRolesAndPermissions()
}

// Обработка ошибок
func handleError(w http.ResponseWriter, err error, message string, statusCode int) {
	logger.WithFields(logrus.Fields{
		"error": err,
	}).Error(message)
	http.Error(w, message, statusCode)
}

// Обработчик для отправки сообщений в поддержку
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

		// Сохраняем сообщение в базу данных
		supportMessage := SupportMessage{
			UserEmail:  userEmail,
			Subject:    subject,
			Message:    message,
			Attachment: attachmentPath,
		}

		if err := db.Create(&supportMessage).Error; err != nil {
			handleError(w, err, "Failed to save support message1", http.StatusInternalServerError)
			return
		}

		// Отправляем email
		err = sendEmail(userEmail, subject, message, attachmentPath)
		if err != nil {
			handleError(w, err, "Failed to send email", http.StatusInternalServerError)
			return
		}

		// Перенаправление на страницу с успешным уведомлением
		http.Redirect(w, r, "/support?success=1", http.StatusSeeOther)
	}
}

// Обновляем функцию отправки email для поддержки вложений
func sendEmail(to, subject, body, attachmentPath string) error {
	logger.WithFields(logrus.Fields{
		"to":             to,
		"subject":        subject,
		"has_attachment": attachmentPath != "",
	}).Info("Attempting to send email")

	// Настройки SMTP
	m := gomail.NewMessage()
	m.SetHeader("From", "adilhan2040@gmail.com") // Ваш email
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	// Добавляем вложение, если оно есть
	if attachmentPath != "" {
		// Проверяем существование файла
		if _, err := os.Stat(attachmentPath); err == nil {
			m.Attach(attachmentPath)
			logger.WithField("attachment", attachmentPath).Info("Added attachment to email")
		} else {
			logger.WithError(err).Error("Attachment file not found")
			return fmt.Errorf("attachment file not found: %v", err)
		}
	}

	// Создаем SMTP клиент
	d := gomail.NewDialer(
		"smtp.gmail.com",        // SMTP сервер
		587,                     // Порт
		"adilhan2040@gmail.com", // Ваш email
		"cnidyxyehqdnbqlp",      // Ваш пароль приложения
	)

	// Отправляем email
	if err := d.DialAndSend(m); err != nil {
		logger.WithFields(logrus.Fields{
			"error": err,
			"to":    to,
		}).Error("Failed to send email")
		return err
	}

	logger.WithFields(logrus.Fields{
		"to": to,
	}).Info("Email sent successfully")
	return nil
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

// Обработчик для отображения товаров
func productsHandler(w http.ResponseWriter, r *http.Request) {
	userIP := r.RemoteAddr
	userAgent := r.UserAgent()

	// Логирование действия
	logToFile(UserActionLog{
		UserIP:    userIP,
		UserAgent: userAgent,
		Endpoint:  "/products",
		Method:    r.Method,
		Action:    "View or filter products",
		Params:    r.URL.RawQuery, // Включает параметры фильтрации, если они есть
		CreatedAt: time.Now(),
	})

	var devices []Device
	query := db

	// Фильтрация по каталогу
	catalog := r.URL.Query().Get("catalog")
	if catalog != "" {
		query = query.Where("catalog = ?", catalog)
	}

	// Фильтрация по цене
	minPrice := r.URL.Query().Get("min_price")
	if minPrice != "" {
		if min, err := strconv.ParseFloat(minPrice, 64); err == nil {
			query = query.Where("price >= ?", min)
		}
	}
	maxPrice := r.URL.Query().Get("max_price")
	if maxPrice != "" {
		if max, err := strconv.ParseFloat(maxPrice, 64); err == nil {
			query = query.Where("price <= ?", max)
		}
	}

	// Сортировка
	sortBy := r.URL.Query().Get("sort_by")
	if sortBy != "" {
		sortOrder := r.URL.Query().Get("sort_order")
		if sortOrder != "desc" {
			sortOrder = "asc"
		}
		query = query.Order(fmt.Sprintf("%s %s", sortBy, sortOrder))
	}

	// Пагинация
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize := 5
	offset := (page - 1) * pageSize
	query = query.Offset(offset).Limit(pageSize)

	// Получение данных из базы
	if err := query.Find(&devices).Error; err != nil {
		handleError(w, err, "Failed to fetch devices", http.StatusInternalServerError)
		return
	}

	// Рендеринг HTML-шаблона
	tmpl, err := template.ParseFiles("./public/products.html")
	if err != nil {
		handleError(w, err, "Failed to load template", http.StatusInternalServerError)
		return
	}

	// Передача данных в шаблон
	if err := tmpl.Execute(w, devices); err != nil {
		handleError(w, err, "Failed to render template", http.StatusInternalServerError)
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

// Обновляем функцию generateVerificationCode
func generateVerificationCode() string {
	// Генерируем случайный код из 6 цифр
	code := fmt.Sprintf("%06d", rand.Intn(1000000))
	return code
}

// Функция для отправки email с кодом подтверждения
func sendVerificationEmail(userEmail, verificationCode string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", "adilhan2040@gmail.com")
	m.SetHeader("To", userEmail)
	m.SetHeader("Subject", "Email Verification")
	m.SetBody("text/plain", fmt.Sprintf("Click the link to verify your email: http://localhost:3000/verify?code=%s", verificationCode))

	d := gomail.NewDialer("smtp.gmail.com", 587, "adilhan2040@gmail.com", "cnidyxyehqdnbqlp")
	return d.DialAndSend(m)
}

// Обновляем обработчик регистрации
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl, err := template.ParseFiles("public/register.html")
		if err != nil {
			handleError(w, err, "Failed to load template", http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
		return
	}

	if r.Method == http.MethodPost {
		var user User
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			logger.WithError(err).Error("Failed to decode registration request")
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Проверяем, не существует ли уже пользователь
		var existingUser User
		if err := db.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
			logger.WithField("email", user.Email).Error("User already exists")
			http.Error(w, "User already exists", http.StatusConflict)
			return
		}

		// Генерируем уникальный токен для верификации
		verificationToken := generateVerificationToken()

		// Хешируем пароль
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.PasswordHash), bcrypt.DefaultCost)
		if err != nil {
			logger.WithError(err).Error("Failed to hash password")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Создаем нового пользователя
		newUser := User{
			Email:             user.Email,
			PasswordHash:      string(hashedPassword),
			VerificationToken: verificationToken,
			IsVerified:        false,
		}

		// Сохраняем пользователя в базе данных
		if err := db.Create(&newUser).Error; err != nil {
			logger.WithError(err).Error("Failed to create user")
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}

		// Формируем ссылку для верификации
		verificationLink := fmt.Sprintf("http://localhost:3000/verify-email?token=%s", verificationToken)

		// Отправляем email со ссылкой верификации
		emailBody := fmt.Sprintf(`
			<h1>Welcome to our service!</h1>
			<p>Please click the link below to verify your email address:</p>
			<p><a href="%s">Verify Email</a></p>
			<p>If the link doesn't work, copy and paste this URL into your browser:</p>
			<p>%s</p>
		`, verificationLink, verificationLink)

		if err := sendEmail(user.Email, "Email Verification", emailBody, ""); err != nil {
			logger.WithFields(logrus.Fields{
				"error": err,
				"email": user.Email,
			}).Error("Failed to send verification email")

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{
				"message": "User created but verification email failed to send",
			})
			return
		}

		logger.WithFields(logrus.Fields{
			"email": user.Email,
		}).Info("User registered successfully and verification email sent")

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Registration successful! Please check your email to verify your account.",
		})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// Добавляем функцию для генерации токена верификации
func generateVerificationToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// Добавляем обработчик верификации email
func verifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Verification token is required", http.StatusBadRequest)
		return
	}

	var user User
	if err := db.Where("verification_token = ?", token).First(&user).Error; err != nil {
		logger.WithError(err).Error("Invalid verification token")
		http.Error(w, "Invalid verification token", http.StatusBadRequest)
		return
	}

	// Обновляем статус верификации пользователя
	user.IsVerified = true
	user.VerificationToken = "" // Очищаем токен после верификации
	if err := db.Save(&user).Error; err != nil {
		logger.WithError(err).Error("Failed to update user verification status")
		http.Error(w, "Failed to verify email", http.StatusInternalServerError)
		return
	}

	// Отображаем страницу успешной верификации
	w.Header().Set("Content-Type", "text/html")
	successHTML := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>Email Verified</title>
		<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
	</head>
	<body>
		<div class="container mt-5">
			<div class="alert alert-success" role="alert">
				<h4 class="alert-heading">Email Verified Successfully!</h4>
				<p>Your email has been verified. You can now <a href="/login">login</a> to your account.</p>
			</div>
		</div>
	</body>
	</html>
	`
	w.Write([]byte(successHTML))
}

// Обработчик для подтверждения email
func verifyHandler(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Verification token is required", http.StatusBadRequest)
		return
	}

	var user User
	if err := db.Where("verification_token = ?", token).First(&user).Error; err != nil {
		logger.WithError(err).Error("Invalid verification token")
		http.Error(w, "Invalid verification token", http.StatusBadRequest)
		return
	}

	// Обновляем статус верификации пользователя
	user.IsVerified = true
	user.VerificationToken = "" // Очищаем токен после верификации
	if err := db.Save(&user).Error; err != nil {
		logger.WithError(err).Error("Failed to update user verification status")
		http.Error(w, "Failed to verify email", http.StatusInternalServerError)
		return
	}

	// Перенаправляем на страницу входа с сообщением об успешной верификации
	http.Redirect(w, r, "/login?verified=1", http.StatusSeeOther)
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// Проверка пароля
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		logger.WithError(err).Error("Password hash comparison failed")
		return false
	}
	return true
}

// Генерация OTP
func generateOTP() string {
	otp := strconv.Itoa(rand.Intn(1000000)) // Генерация 6-значного OTP
	return otp
}

// Отправка OTP (в реальном проекте отправка на email или SMS)
func sendOTP(otp, email string) {
	fmt.Printf("OTP for user %s is: %s\n", email, otp) // Это просто пример
}

// Обновляем функцию loginHandler
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		tmpl, err := template.ParseFiles("public/login.html")
		if err != nil {
			handleError(w, err, "Failed to load template", http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, nil)
		return
	}

	if r.Method == http.MethodPost {
		email := r.FormValue("email")
		password := r.FormValue("password")

		logger.WithFields(logrus.Fields{
			"email":           email,
			"password_length": len(password),
		}).Info("Login attempt")

		var user User
		result := db.Where("email = ?", email).First(&user)
		if result.Error != nil {
			logger.WithFields(logrus.Fields{
				"error": result.Error,
				"email": email,
			}).Error("User not found")
			http.Error(w, "Неверный email или пароль", http.StatusUnauthorized)
			return
		}

		logger.WithFields(logrus.Fields{
			"user_id":              user.ID,
			"email":                user.Email,
			"password_hash_length": len(user.PasswordHash),
		}).Info("User found")

		if !checkPasswordHash(password, user.PasswordHash) {
			logger.WithFields(logrus.Fields{
				"email":          email,
				"input_password": password,
				"stored_hash":    user.PasswordHash,
			}).Error("Password verification failed")
			http.Error(w, "Неверный email или пароль", http.StatusUnauthorized)
			return
		}

		logger.Info("Успешная аутентификация")

		// Генерация OTP
		otp := generateOTP()
		otpExpiresAt := time.Now().Add(10 * time.Minute)

		// Обновляем пользователя с OTP
		if err := db.Model(&user).Updates(map[string]interface{}{
			"otp":            otp,
			"otp_expires_at": otpExpiresAt,
		}).Error; err != nil {
			logger.WithError(err).Error("Ошибка при обновлении OTP")
			http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
			return
		}

		// Отправляем OTP на email пользователя
		emailBody := fmt.Sprintf(`
			<h1>Your OTP Code</h1>
			<p>Your one-time password is: <strong>%s</strong></p>
			<p>This code will expire in 5 minutes.</p>
		`, otp)

		if err := sendEmail(user.Email, "Your OTP Code", emailBody, ""); err != nil {
			logger.WithError(err).Error("Failed to send OTP email")
			http.Error(w, "Failed to send OTP", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Пароль верный. Проверьте email для получения OTP"))
		return
	}
}

// Обновляем функцию otpVerifyHandler
func otpVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := r.FormValue("email")
	otp := r.FormValue("otp")

	var user User
	if err := db.Preload("Roles.Permissions").Where("email = ?", email).First(&user).Error; err != nil {
		logger.WithError(err).Error("User not found")
		http.Error(w, "Invalid email", http.StatusUnauthorized)
		return
	}

	// Проверяем OTP
	if user.OTP != otp || time.Now().After(user.OTPExpiresAt) {
		logger.Error("Invalid OTP or OTP expired")
		http.Error(w, "Invalid OTP", http.StatusUnauthorized)
		return
	}

	// Очищаем OTP
	if err := db.Model(&user).Updates(map[string]interface{}{
		"otp":            "",
		"otp_expires_at": time.Now(),
	}).Error; err != nil {
		logger.WithError(err).Error("Failed to clear OTP")
	}

	// Создаем JWT токен с информацией о ролях пользователя
	claims := jwt.MapClaims{
		"email": user.Email,
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
		"roles": getRoleNames(user.Roles), // Добавляем роли в токен
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		logger.WithError(err).Error("Failed to generate token")
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token": tokenString,
		"roles": getRoleNames(user.Roles),
	})
}

// Вспомогательная функция для получения имен ролей
func getRoleNames(roles []Role) []string {
	var roleNames []string
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
	}
	return roleNames
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

// Обработчик для отправки SMS
func handleSendSMS(w http.ResponseWriter, r *http.Request) {
	phone := r.FormValue("phone")
	if phone == "" {
		http.Error(w, "Номер телефона обязателен", http.StatusBadRequest)
		return
	}

	code := generateSMSCode()
	smsCodesStorage[phone] = SMSCode{
		Phone:     phone,
		Code:      code,
		CreatedAt: time.Now(),
		Used:      false,
	}

	if err := sendSMS(phone, code); err != nil {
		http.Error(w, "Ошибка отправки SMS", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// Обработчик для проверки SMS кода и выдачи JWT токена
func handleVerifySMS(w http.ResponseWriter, r *http.Request) {
	phone := r.FormValue("phone")
	code := r.FormValue("code")

	smsCode, exists := smsCodesStorage[phone]
	if !exists || smsCode.Used || time.Since(smsCode.CreatedAt) > 5*time.Minute {
		http.Error(w, "Неверный код или код истек", http.StatusBadRequest)
		return
	}

	if smsCode.Code != code {
		http.Error(w, "Неверный код", http.StatusBadRequest)
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

	// Помечаем код как использованный
	smsCode.Used = true
	smsCodesStorage[phone] = smsCode

	// Отправляем токен клиенту
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

// Middleware для проверки JWT токена
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Отсутствует токен авторизации", http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Недействительный токен", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// Обработчик для получения списка ролей
func listRolesHandler(w http.ResponseWriter, r *http.Request) {
	var roles []Role
	if err := db.Preload("Permissions").Find(&roles).Error; err != nil {
		handleError(w, err, "Failed to fetch roles", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(roles)
}

// Обработчик для получения списка разрешений
func listPermissionsHandler(w http.ResponseWriter, r *http.Request) {
	var permissions []Permission
	if err := db.Find(&permissions).Error; err != nil {
		handleError(w, err, "Failed to fetch permissions", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(permissions)
}

// Обработчик для добавления роли
func addRoleHandler(w http.ResponseWriter, r *http.Request) {
	var roleData struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Permissions []uint `json:"permissions"`
	}

	if err := json.NewDecoder(r.Body).Decode(&roleData); err != nil {
		handleError(w, err, "Invalid request data", http.StatusBadRequest)
		return
	}

	var permissions []Permission
	if err := db.Find(&permissions, roleData.Permissions).Error; err != nil {
		handleError(w, err, "Failed to fetch permissions", http.StatusInternalServerError)
		return
	}

	role := Role{
		Name:        roleData.Name,
		Description: roleData.Description,
		Permissions: permissions,
	}

	if err := db.Create(&role).Error; err != nil {
		handleError(w, err, "Failed to create role", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// Обновляем middleware для проверки разрешений
func permissionMiddleware(requiredPermission string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Получаем токен из заголовка
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				logger.Error("No Authorization header")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Убираем префикс "Bearer " если он есть
			tokenString := authHeader
			if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
				tokenString = authHeader[7:]
			}

			// Парсим токен
			claims := jwt.MapClaims{}
			token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
				return jwtSecret, nil
			})

			if err != nil {
				logger.WithError(err).Error("Failed to parse token")
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			if !token.Valid {
				logger.Error("Token is invalid")
				http.Error(w, "Invalid token", http.StatusUnauthorized)
				return
			}

			// Получаем email пользователя из токена
			email, ok := claims["email"].(string)
			if !ok {
				logger.Error("No email in token claims")
				http.Error(w, "Invalid token claims", http.StatusUnauthorized)
				return
			}

			// Получаем пользователя с его ролями и разрешениями
			var user User
			if err := db.Preload("Roles.Permissions").Where("email = ?", email).First(&user).Error; err != nil {
				logger.WithError(err).Error("User not found")
				http.Error(w, "User not found", http.StatusUnauthorized)
				return
			}

			// Проверяем наличие требуемого разрешения
			hasPermission := false
			for _, role := range user.Roles {
				for _, perm := range role.Permissions {
					logger.WithFields(logrus.Fields{
						"user_email":          email,
						"permission_required": requiredPermission,
						"permission_found":    perm.Name,
					}).Info("Checking permission")

					if perm.Name == requiredPermission {
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
					"user_email":          email,
					"permission_required": requiredPermission,
				}).Error("Permission denied")
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next(w, r)
		}
	}
}

func createDefaultRolesAndPermissions() {
	// Создаем базовые разрешения
	permissions := []Permission{
		{Name: "manage_roles", Description: "Can manage roles and permissions"},
		{Name: "view_products", Description: "Can view products"},
		{Name: "manage_products", Description: "Can manage products"},
		{Name: "manage_users", Description: "Can manage users"},
	}

	for _, perm := range permissions {
		if err := db.FirstOrCreate(&perm, Permission{Name: perm.Name}).Error; err != nil {
			logger.WithError(err).Error("Failed to create permission")
		}
	}

	// Создаем роль администратора
	adminRole := Role{
		Name:        "admin",
		Description: "Administrator role with full access",
	}

	if err := db.FirstOrCreate(&adminRole, Role{Name: "admin"}).Error; err != nil {
		logger.WithError(err).Error("Failed to create admin role")
		return
	}

	// Получаем все разрешения
	var allPermissions []Permission
	if err := db.Find(&allPermissions).Error; err != nil {
		logger.WithError(err).Error("Failed to fetch permissions")
		return
	}

	// Назначаем все разрешения роли администратора
	if err := db.Model(&adminRole).Association("Permissions").Replace(allPermissions); err != nil {
		logger.WithError(err).Error("Failed to assign permissions to admin role")
		return
	}

	// Находим первого пользователя и назначаем ему роль администратора
	var user User
	if err := db.First(&user).Error; err != nil {
		logger.WithError(err).Error("No users found")
		return
	}

	// Назначаем роль администратора пользователю
	if err := db.Model(&user).Association("Roles").Append(&adminRole); err != nil {
		logger.WithError(err).Error("Failed to assign admin role to user")
		return
	}

	logger.WithFields(logrus.Fields{
		"user_email": user.Email,
		"role":       "admin",
	}).Info("Successfully set up admin role and permissions")
}

// Обновляем обработчик для удаления роли
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

	// Проверяем существование роли
	var role Role
	if err := db.First(&role, roleID).Error; err != nil {
		logger.WithError(err).Error("Role not found")
		http.Error(w, "Role not found", http.StatusNotFound)
		return
	}

	// Проверяем, не пытаемся ли удалить роль admin
	if role.Name == "admin" {
		logger.Error("Attempt to delete admin role")
		http.Error(w, "Cannot delete admin role", http.StatusForbidden)
		return
	}

	// Начинаем транзакцию
	tx := db.Begin()

	// Удаляем связи роли с разрешениями
	if err := tx.Model(&role).Association("Permissions").Clear(); err != nil {
		tx.Rollback()
		logger.WithError(err).Error("Failed to clear role permissions")
		http.Error(w, "Failed to delete role permissions", http.StatusInternalServerError)
		return
	}

	// Удаляем связи роли с пользователями
	if err := tx.Table("user_roles").Where("role_id = ?", roleID).Delete(&struct{}{}).Error; err != nil {
		tx.Rollback()
		logger.WithError(err).Error("Failed to clear user roles")
		http.Error(w, "Failed to delete user roles", http.StatusInternalServerError)
		return
	}

	// Удаляем саму роль
	if err := tx.Delete(&role).Error; err != nil {
		tx.Rollback()
		logger.WithError(err).Error("Failed to delete role")
		http.Error(w, "Failed to delete role", http.StatusInternalServerError)
		return
	}

	// Подтверждаем транзакцию
	if err := tx.Commit().Error; err != nil {
		logger.WithError(err).Error("Failed to commit transaction")
		http.Error(w, "Failed to delete role", http.StatusInternalServerError)
		return
	}

	logger.WithField("role_id", roleID).Info("Role deleted successfully")
	w.WriteHeader(http.StatusOK)
}

// Обработчик для получения информации о роли
func getRoleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	roleID := r.URL.Query().Get("id")
	if roleID == "" {
		http.Error(w, "Role ID is required", http.StatusBadRequest)
		return
	}

	var role Role
	if err := db.Preload("Permissions").First(&role, roleID).Error; err != nil {
		http.Error(w, "Role not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(role)
}

// Обработчик для обновления роли
func updateRoleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var roleData struct {
		ID          uint   `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Permissions []uint `json:"permissions"`
	}

	if err := json.NewDecoder(r.Body).Decode(&roleData); err != nil {
		http.Error(w, "Invalid request data", http.StatusBadRequest)
		return
	}

	// Проверяем существование роли
	var role Role
	if err := db.First(&role, roleData.ID).Error; err != nil {
		http.Error(w, "Role not found", http.StatusNotFound)
		return
	}

	// Не позволяем изменять имя роли admin
	if role.Name == "admin" && roleData.Name != "admin" {
		http.Error(w, "Cannot modify admin role name", http.StatusForbidden)
		return
	}

	// Обновляем основные данные роли
	role.Name = roleData.Name
	role.Description = roleData.Description

	// Получаем выбранные разрешения
	var permissions []Permission
	if err := db.Find(&permissions, roleData.Permissions).Error; err != nil {
		http.Error(w, "Failed to fetch permissions", http.StatusInternalServerError)
		return
	}

	// Обновляем роль и её разрешения
	tx := db.Begin()
	if err := tx.Save(&role).Error; err != nil {
		tx.Rollback()
		http.Error(w, "Failed to update role", http.StatusInternalServerError)
		return
	}

	if err := tx.Model(&role).Association("Permissions").Replace(permissions); err != nil {
		tx.Rollback()
		http.Error(w, "Failed to update role permissions", http.StatusInternalServerError)
		return
	}

	tx.Commit()

	w.WriteHeader(http.StatusOK)
}

func main() {
	// Инициализация базы данных
	initDB()

	// Получаем порт из переменной окружения
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	// Обновляем адрес сервера для работы с Render
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: http.DefaultServeMux,
	}

	// Обслуживание статических файлов
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./public"))))

	// Маршрут для отображения продуктов
	http.HandleFunc("/products", rateLimitMiddleware(productsHandler))
	http.HandleFunc("/support", supportHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/verify", verifyHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/otpVerify", otpVerifyHandler)
	http.HandleFunc("/api/send-sms", handleSendSMS)
	http.HandleFunc("/api/verify-sms", handleVerifySMS)
	http.HandleFunc("/api/list-roles", listRolesHandler)
	http.HandleFunc("/api/list-permissions", listPermissionsHandler)
	http.HandleFunc("/api/add-role", addRoleHandler)

	// Пример защищенного маршрута
	http.HandleFunc("/api/protected", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Защищенные данные"))
	}))

	// Обновляем маршрут для страницы управления ролями
	http.HandleFunc("/admin/roles", func(w http.ResponseWriter, r *http.Request) {
		// Получаем токен из заголовка
		authHeader := r.Header.Get("Authorization")
		logger.WithFields(logrus.Fields{
			"auth_header": authHeader,
			"method":      r.Method,
			"path":        r.URL.Path,
		}).Info("Accessing roles page")

		if authHeader == "" {
			// Если токена нет, возможно это первоначальный запрос HTML страницы
			if r.Header.Get("Accept") == "application/json" {
				// Для API запросов требуем токен
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			// Для обычных запросов отдаем HTML страницу
			http.ServeFile(w, r, "public/admin/roles.html")
			return
		}

		// Если есть токен, проверяем права доступа
		tokenString := authHeader
		if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			tokenString = authHeader[7:]
		}

		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			logger.WithError(err).Error("Invalid token")
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		email, ok := claims["email"].(string)
		if !ok {
			logger.Error("No email in token claims")
			http.Error(w, "Invalid token claims", http.StatusUnauthorized)
			return
		}

		var user User
		if err := db.Preload("Roles.Permissions").Where("email = ?", email).First(&user).Error; err != nil {
			logger.WithError(err).Error("User not found")
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}

		// Проверяем наличие разрешения manage_roles
		hasPermission := false
		for _, role := range user.Roles {
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
			logger.WithField("email", email).Error("Permission denied")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Если все проверки пройдены, отдаем HTML страницу
		http.ServeFile(w, r, "public/admin/roles.html")
	})

	// Обновляем маршруты API для работы с ролями
	http.HandleFunc("/admin/roles/list", permissionMiddleware("manage_roles")(listRolesHandler))
	http.HandleFunc("/admin/permissions/list", permissionMiddleware("manage_roles")(listPermissionsHandler))
	http.HandleFunc("/admin/roles/add", permissionMiddleware("manage_roles")(addRoleHandler))

	// Добавьте эти маршруты перед запуском сервера
	http.HandleFunc("/admin/roles/delete", permissionMiddleware("manage_roles")(deleteRoleHandler))
	http.HandleFunc("/admin/roles/get", permissionMiddleware("manage_roles")(getRoleHandler))
	http.HandleFunc("/admin/roles/update", permissionMiddleware("manage_roles")(updateRoleHandler))

	// Добавляем маршрут для верификации email
	http.HandleFunc("/verify-email", verifyEmailHandler)

	// Запуск сервера в отдельной горутине
	go func() {
		logger.Info("Server is running on port " + port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("Failed to start server")
		}
	}()

	// Обработка мягкого завершения
	gracefulShutdown(srv)
}
