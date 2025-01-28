package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Определяем структуру Product для тестов
type Product struct {
	gorm.Model
	Name    string  `json:"name" gorm:"column:name"`
	Price   float64 `json:"price" gorm:"column:price"`
	Catalog string  `json:"catalog" gorm:"column:catalog"`
}

// Указываем имя таблицы
func (Product) TableName() string {
	return "products"
}

// Константы для тестовой базы данных
const (
	testDBHost     = "localhost"
	testDBUser     = "postgres"
	testDBPassword = "newpassword"
	testDBName     = "test_db"
	testDBPort     = "5432"
)

// Unit тест для функции проверки пароля
func TestPasswordHashing(t *testing.T) {
	// Подготовка
	password := "testPassword123"

	// Действие
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	// Проверка
	assert.NoError(t, err)
	assert.NotEqual(t, password, string(hashedPassword))

	// Проверяем совпадение паролей
	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	assert.NoError(t, err)
}

// Интеграционный тест для проверки фильтрации продуктов
func TestProductFiltering(t *testing.T) {
	// Подготовка тестовой базы данных
	testDB, err := setupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	// Временно заменяем глобальную переменную db на тестовую
	originalDB := db
	db = testDB
	defer func() {
		if db != nil {
			sqlDB, err := db.DB()
			if err == nil {
				sqlDB.Close()
			}
		}
		db = originalDB
	}()

	// Очищаем таблицу перед тестом
	err = db.Exec("DROP TABLE IF EXISTS products").Error
	assert.NoError(t, err)

	// Создаем таблицу
	err = db.AutoMigrate(&Product{})
	assert.NoError(t, err)

	// Создаем тестовые продукты
	testProducts := []Product{
		{Name: "Test Product 1", Price: 100, Catalog: "Electronics"},
		{Name: "Test Product 2", Price: 200, Catalog: "Electronics"},
		{Name: "Test Product 3", Price: 300, Catalog: "Clothing"},
	}

	for _, product := range testProducts {
		result := db.Create(&product)
		assert.NoError(t, result.Error)
	}

	// Создаем тестовый HTTP запрос
	req := httptest.NewRequest("GET", "/products?catalog=Electronics&min_price=150", nil)
	w := httptest.NewRecorder()

	// Выполняем запрос
	productsHandler(w, req)

	// Проверяем результат
	assert.Equal(t, http.StatusOK, w.Code)

	var response struct {
		Products []Product `json:"products"`
	}
	err = json.NewDecoder(w.Body).Decode(&response)
	assert.NoError(t, err)

	// Проверяем, что получили только один продукт из категории Electronics с ценой выше 150
	assert.Len(t, response.Products, 1)
	if len(response.Products) > 0 {
		assert.Equal(t, "Test Product 2", response.Products[0].Name)
	}
}

// End-to-end тест для процесса регистрации и входа
func TestRegistrationAndLogin(t *testing.T) {
	// Пропускаем этот тест, если нет подключения к базе данных
	testDB, err := setupTestDB()
	if err != nil {
		t.Skip("Skipping test due to database connection issues")
	}

	// Временно заменяем глобальную переменную db на тестовую
	originalDB := db
	db = testDB
	defer func() {
		db = originalDB
		// Очищаем тестовые данные
		db.Exec("DELETE FROM users")
	}()

	// Подготовка тестового сервера
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/register":
			registerHandler(w, r)
		case "/login":
			loginHandler(w, r)
		case "/otpVerify":
			otpVerifyHandler(w, r)
		}
	}))
	defer ts.Close()

	// Тестовые данные
	testUser := struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{
		Email:    "test@example.com",
		Password: "testPassword123",
	}

	// Шаг 1: Регистрация
	registerData, _ := json.Marshal(testUser)
	resp, err := http.Post(ts.URL+"/register", "application/json", bytes.NewBuffer(registerData))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	// Шаг 2: Вход
	loginData, _ := json.Marshal(testUser)
	resp, err = http.Post(ts.URL+"/login", "application/json", bytes.NewBuffer(loginData))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Получаем OTP из ответа
	var loginResponse struct {
		Message string `json:"message"`
	}
	json.NewDecoder(resp.Body).Decode(&loginResponse)

	// Шаг 3: Проверка OTP
	otpData := struct {
		Email string `json:"email"`
		OTP   string `json:"otp"`
	}{
		Email: testUser.Email,
		OTP:   "123456", // Тестовый OTP
	}

	otpRequestData, _ := json.Marshal(otpData)
	resp, err = http.Post(ts.URL+"/otpVerify", "application/json", bytes.NewBuffer(otpRequestData))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Проверяем, что получили JWT токен
	var otpResponse struct {
		Token string `json:"token"`
	}
	json.NewDecoder(resp.Body).Decode(&otpResponse)
	assert.NotEmpty(t, otpResponse.Token)
}

// Вспомогательная функция для создания тестовой базы данных
func setupTestDB() (*gorm.DB, error) {
	// Формируем строку подключения
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
		testDBHost, testDBUser, testDBPassword, testDBName, testDBPort)

	// Открываем соединение с базой данных
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to test database: %v", err)
	}

	return db, nil
}
