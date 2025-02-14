package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"time"

	"github.com/jung-kurt/gofpdf"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gopkg.in/gomail.v2"
)

var (
	client *mongo.Client
	db     *mongo.Database
)

type Transaction struct {
	ID        primitive.ObjectID `bson:"_id" json:"id"`
	UserID    primitive.ObjectID `bson:"user_id" json:"user_id"`
	CartID    primitive.ObjectID `bson:"cart_id" json:"cart_id"`
	Total     float64            `bson:"total" json:"total"`
	Status    string             `bson:"status" json:"status"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time          `bson:"updated_at" json:"updated_at"`
}

func main() {
	// Подключение к MongoDB
	ctx := context.Background()
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	var err error
	client, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)

	db = client.Database("payment_service")

	// Настройка маршрутов
	http.HandleFunc("/payment", paymentHandler)
	http.HandleFunc("/process-payment", processPaymentHandler)

	log.Println("Payment service starting on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

func paymentHandler(w http.ResponseWriter, r *http.Request) {
	transactionID := r.URL.Query().Get("transaction_id")
	if transactionID == "" {
		http.Error(w, "Transaction ID is required", http.StatusBadRequest)
		return
	}

	tmpl := template.Must(template.ParseFiles("payment.html"))
	tmpl.Execute(w, map[string]string{
		"TransactionID": transactionID,
	})
}

func processPaymentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var paymentData struct {
		TransactionID string `json:"transaction_id"`
		CardNumber    string `json:"card_number"`
		ExpiryDate    string `json:"expiry_date"`
		CVV           string `json:"cvv"`
	}

	if err := json.NewDecoder(r.Body).Decode(&paymentData); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Здесь должна быть реальная обработка платежа
	// Для демонстрации просто проверяем, что номер карты не пустой
	if paymentData.CardNumber == "" {
		http.Error(w, "Invalid card number", http.StatusBadRequest)
		return
	}

	// Обновляем статус транзакции
	objID, _ := primitive.ObjectIDFromHex(paymentData.TransactionID)
	_, err := client.Database("ass4").Collection("transactions").UpdateOne(
		context.Background(),
		bson.M{"_id": objID},
		bson.M{"$set": bson.M{
			"status":     "completed",
			"updated_at": time.Now(),
		}},
	)

	if err != nil {
		http.Error(w, "Failed to update transaction", http.StatusInternalServerError)
		return
	}

	// Генерируем и отправляем чек
	if err := generateAndSendReceipt(paymentData.TransactionID); err != nil {
		log.Printf("Failed to generate and send receipt: %v", err)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Payment processed successfully",
	})
}

func generateAndSendReceipt(transactionID string) error {
	// Создаем PDF
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 16)

	// Добавляем содержимое чека
	pdf.Cell(40, 10, "Фискальный чек")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 12)
	pdf.Cell(40, 10, fmt.Sprintf("Транзакция: %s", transactionID))
	pdf.Ln(10)
	pdf.Cell(40, 10, fmt.Sprintf("Дата: %s", time.Now().Format("2006-01-02 15:04:05")))

	// Сохраняем PDF
	filename := fmt.Sprintf("receipts/%s.pdf", transactionID)
	if err := pdf.OutputFileAndClose(filename); err != nil {
		return err
	}

	// Отправляем email
	return sendReceiptEmail(filename, "uaki_seitzhanov@mail.ru") // Замените на реальный email
}

func sendReceiptEmail(filename, email string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", "adilhan2040@gmail.com")
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Ваш чек")
	m.SetBody("text/plain", "Спасибо за покупку! Ваш чек во вложении.")
	m.Attach(filename)

	d := gomail.NewDialer("smtp.gmail.com", 587, "adilhan2040@gmail.com", "cnidyxyehqdnbqlp")
	return d.DialAndSend(m)
}
