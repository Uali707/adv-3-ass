const express = require('express');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);

app.use(express.static('public'));

// Хранение активных чатов
const activeChats = new Map();

io.on('connection', (socket) => {
    console.log('Пользователь подключился');

    // Создание нового чата
    socket.on('createChat', (userId) => {
        const chatId = generateChatId();
        activeChats.set(chatId, {
            userId: userId,
            messages: [],
            status: 'active'
        });
        socket.join(chatId);
        socket.emit('chatCreated', chatId);
    });

    // Обработка сообщений
    socket.on('sendMessage', (data) => {
        const { chatId, message, userId } = data;
        const chat = activeChats.get(chatId);
        
        if (chat && chat.status === 'active') {
            const messageObj = {
                text: message,
                userId: userId,
                timestamp: new Date()
            };
            chat.messages.push(messageObj);
            io.to(chatId).emit('newMessage', messageObj);
        }
    });

    // Закрытие чата администратором
    socket.on('closeChat', (chatId) => {
        const chat = activeChats.get(chatId);
        if (chat) {
            chat.status = 'inactive';
            io.to(chatId).emit('chatClosed');
            activeChats.delete(chatId);
        }
    });

    socket.on('disconnect', () => {
        console.log('Пользователь отключился');
    });
});

function generateChatId() {
    return Math.random().toString(36).substring(7);
}

http.listen(3000, () => {
    console.log('Сервер запущен на порту 3000');
}); 