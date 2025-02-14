package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

var testDB *gorm.DB

// Unit тесты
func TestGenerateVerificationCode(t *testing.T) {
	// Тестируем генерацию кода верификации
	code := generateVerificationCode()
	assert.Len(t, code, 6)
	_, err := fmt.Sscanf(code, "%d", new(int))
	assert.NoError(t, err, "Код должен состоять только из цифр")
}

func TestHashPassword(t *testing.T) {
	// Тестируем хеширование пароля
	password := "testPassword123"
	hash, err := hashPassword(password)

	assert.NoError(t, err)
	assert.NotEqual(t, password, hash)

	// Проверяем правильность хеша
	isValid := checkPasswordHash(password, hash)
	assert.True(t, isValid)
}

func TestGenerateOTP(t *testing.T) {
	// Тестируем генерацию OTP
	otp := generateOTP()
	assert.Len(t, otp, 6)
	_, err := fmt.Sscanf(otp, "%d", new(int))
	assert.NoError(t, err, "OTP должен состоять только из цифр")
}

// Исправленный интеграционный тест для регистрации и входа
func TestUserRegistrationAndLogin(t *testing.T) {
	// Очищаем БД перед тестом
	cleanupTestDB()

	initDB()

	// Создаем тестовые данные для регистрации
	registrationData := struct {
		Email        string `json:"email"`
		PasswordHash string `json:"password_hash"`
	}{
		Email:        "test@example.com",
		PasswordHash: "testPassword123",
	}

	// Регистрация
	userJSON, _ := json.Marshal(registrationData)
	req := httptest.NewRequest("POST", "/register", bytes.NewBuffer(userJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	registerHandler(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	// Верифицируем пользователя напрямую через БД
	var user User
	result := db.Where("email = ?", registrationData.Email).First(&user)
	if result.Error != nil {
		t.Fatalf("Failed to find user after registration: %v", result.Error)
	}
	user.IsVerified = true
	db.Save(&user)

	// Вход с правильными данными
	loginData := map[string]string{
		"email":         registrationData.Email,
		"password_hash": registrationData.PasswordHash,
	}

	loginJSON, err := json.Marshal(loginData)
	if err != nil {
		t.Fatalf("Failed to marshal login data: %v", err)
	}

	req = httptest.NewRequest("POST", "/login", bytes.NewBuffer(loginJSON))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	loginHandler(w, req)

	// Добавляем логирование ответа
	t.Logf("Login Response: %s", w.Body.String())
	t.Logf("Login Status Code: %d", w.Code)

	assert.Equal(t, http.StatusOK, w.Code)
}

// Исправленный тест управления ролями
func TestRoleManagement(t *testing.T) {
	initDB()

	// Создаем тестовое разрешение
	permission := Permission{
		Name:        "test_permission",
		Description: "Test permission",
	}
	db.Create(&permission)

	// Создаем тестовую роль
	roleData := struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Permissions []uint `json:"permissions"`
	}{
		Name:        "test_role",
		Description: "Test role description",
		Permissions: []uint{permission.ID},
	}

	roleJSON, _ := json.Marshal(roleData)
	req := httptest.NewRequest("POST", "/api/add-role", bytes.NewBuffer(roleJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Добавляем токен с правами администратора
	token, _ := generateTestJWT("admin@example.com")
	req.Header.Set("Authorization", "Bearer "+token)

	addRoleHandler(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	// Проверяем список ролей
	req = httptest.NewRequest("GET", "/api/list-roles", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()

	listRolesHandler(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var roles []Role
	json.NewDecoder(w.Body).Decode(&roles)

	// Проверяем, что роль существует
	found := false
	for _, role := range roles {
		if role.Name == roleData.Name {
			found = true
			break
		}
	}
	assert.True(t, found, "Созданная роль должна быть в списке")
}

// Исправленный E2E тест
func TestCompleteUserFlow(t *testing.T) {
	initDB()

	// Регистрация
	userData := struct {
		Email        string `json:"email"`
		PasswordHash string `json:"password_hash"`
	}{
		Email:        "e2e@test.com",
		PasswordHash: "testPassword123",
	}

	userJSON, _ := json.Marshal(userData)
	req := httptest.NewRequest("POST", "/register", bytes.NewBuffer(userJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	registerHandler(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	// Верифицируем пользователя напрямую через БД
	var user User
	result := db.Where("email = ?", userData.Email).First(&user)
	if result.Error != nil {
		t.Fatalf("Failed to find user after registration: %v", result.Error)
	}
	user.IsVerified = true
	db.Save(&user)

	// Вход с правильными данными
	loginData := map[string]string{
		"email":         userData.Email,
		"password_hash": userData.PasswordHash,
	}

	loginJSON, err := json.Marshal(loginData)
	if err != nil {
		t.Fatalf("Failed to marshal login data: %v", err)
	}

	req = httptest.NewRequest("POST", "/login", bytes.NewBuffer(loginJSON))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	loginHandler(w, req)

	// Добавляем логирование ответа
	t.Logf("Login Response: %s", w.Body.String())
	t.Logf("Login Status Code: %d", w.Code)

	assert.Equal(t, http.StatusOK, w.Code)

	// Проверка доступа к продуктам
	token, _ := generateTestJWT(userData.Email)
	req = httptest.NewRequest("GET", "/products", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	productsHandler(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// Вспомогательные функции
func generateTestJWT(email string) (string, error) {
	claims := jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
		"roles": []string{"admin"}, // Добавляем роль админа для тестов
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func setup() {
	// Используем отдельную тестовую базу данных
	testDSN := "host=localhost user=postgres password=newpassword dbname=advprog_test port=5432 sslmode=disable"
	var err error
	testDB, err = gorm.Open(postgres.Open(testDSN), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to test database")
	}

	// Сохраняем оригинальное подключение
	originalDB := db

	// Используем тестовую базу только для тестов
	db = testDB

	// Миграция схемы в тестовой базе
	db.AutoMigrate(&User{}, &Role{}, &Permission{}, &Device{}, &SupportMessage{})

	// Очищаем таблицы только в тестовой базе
	db.Exec("TRUNCATE TABLE users CASCADE")
	db.Exec("TRUNCATE TABLE roles CASCADE")
	db.Exec("TRUNCATE TABLE permissions CASCADE")
	db.Exec("TRUNCATE TABLE role_permissions CASCADE")
	db.Exec("TRUNCATE TABLE user_roles CASCADE")

	// Создаем базовые разрешения и роли
	createDefaultRolesAndPermissions()

	// Восстанавливаем оригинальное подключение
	db = originalDB
}

func teardown() {
	// Закрываем соединение с тестовой базой
	if testDB, err := db.DB(); err == nil {
		testDB.Close()
	}
}

func TestMain(m *testing.M) {
	// Конфигурация для тестовой базы данных
	testConfig := &Config{
		DBHost:     "localhost",
		DBPort:     "5432",
		DBUser:     "your_user",
		DBPassword: "your_password",
		DBName:     "test_db", // Используем тестовую базу
	}

	var err error
	testDB, err = InitDB(testConfig)
	if err != nil {
		log.Fatal("Failed to connect to test database:", err)
	}

	// Очищаем таблицы перед каждым запуском тестов
	cleanupTestDB()

	// Запускаем тесты
	code := m.Run()

	// Закрываем соединение
	sqlDB, err := testDB.DB()
	if err == nil {
		sqlDB.Close()
	}

	os.Exit(code)
}

func cleanupTestDB() {
	testDB.Exec("TRUNCATE TABLE user_roles CASCADE")
	testDB.Exec("TRUNCATE TABLE permissions CASCADE")
	testDB.Exec("TRUNCATE TABLE roles CASCADE")
	testDB.Exec("TRUNCATE TABLE users CASCADE")
}
