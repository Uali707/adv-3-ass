const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);

app.use(express.static('public'));

// Хранение активных чатов
const activeChats = new Map();

io.on('connection', (socket) => {
    const isAdmin = socket.handshake.query.isAdmin === 'true';
    console.log('Новое подключение:', isAdmin ? 'Админ' : 'Клиент');

    // Если подключился админ, отправляем ему все активные чаты
    if (isAdmin) {
        console.log('Отправка существующих чатов админу');
        activeChats.forEach((chat, chatId) => {
            if (chat.status === 'active') {
                socket.emit('chatCreated', chatId);
            }
        });
    }

    // Создание нового чата
    socket.on('createChat', (userId) => {
        const chatId = generateChatId();
        console.log('Создан новый чат:', chatId, 'от пользователя:', userId);
        
        activeChats.set(chatId, {
            userId: userId,
            messages: [],
            status: 'active'
        });
        
        // Отправляем ID чата создателю
        socket.emit('chatCreated', chatId);
        
        // Отправляем уведомление всем админам
        socket.broadcast.to('admin').emit('chatCreated', chatId);
    });

    // Если это админ, добавляем его в специальную комнату
    if (isAdmin) {
        socket.join('admin');
    }

    // Обработка сообщений
    socket.on('sendMessage', (data) => {
        console.log('Новое сообщение:', data);
        const { chatId, message, userId } = data;
        const chat = activeChats.get(chatId);
        
        if (chat && chat.status === 'active') {
            const messageObj = {
                text: message,
                userId: userId,
                chatId: chatId,
                timestamp: new Date()
            };
            chat.messages.push(messageObj);
            io.to(chatId).emit('newMessage', messageObj);
            console.log('Сообщение отправлено в чат:', chatId);
        }
    });

    // Закрытие чата администратором
    socket.on('closeChat', (chatId) => {
        console.log('Закрытие чата:', chatId);
        const chat = activeChats.get(chatId);
        if (chat) {
            chat.status = 'inactive';
            io.to(chatId).emit('chatClosed');
            activeChats.delete(chatId);
            console.log('Чат закрыт:', chatId);
        }
    });

    socket.on('disconnect', () => {
        console.log('Отключение:', isAdmin ? 'Админ' : 'Клиент');
    });
});

function generateChatId() {
    return Math.random().toString(36).substring(7);
}

http.listen(3000, () => {
    console.log('Сервер запущен на порту 3000');
}); 