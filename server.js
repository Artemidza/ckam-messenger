const express = require('express');
const socketIo = require('socket.io');
const http = require('http');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Хранилище данных (в реальном проекте используйте БД)
const users = new Map();
const messages = new Map();
const JWT_SECRET = 'ckam-secret-key-2024';

// Middleware для проверки токена
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// API эндпоинты
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, name } = req.body;
    
    // Проверка существующего пользователя
    if (Array.from(users.values()).some(u => u.username === username)) {
      return res.status(400).json({ error: 'Пользователь уже существует' });
    }
    
    // Хеширование пароля
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = {
      id: Date.now().toString(),
      username,
      password: hashedPassword,
      name: name || username,
      online: false,
      socketId: null
    };
    
    users.set(user.id, user);
    
    // Создание JWT токена
    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({ 
      success: true, 
      user: { 
        id: user.id, 
        username: user.username, 
        name: user.name 
      }, 
      token 
    });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Поиск пользователя
    const user = Array.from(users.values()).find(u => u.username === username);
    if (!user) {
      return res.status(400).json({ error: 'Пользователь не найден' });
    }
    
    // Проверка пароля
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Неверный пароль' });
    }
    
    // Создание JWT токена
    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({ 
      success: true, 
      user: { 
        id: user.id, 
        username: user.username, 
        name: user.name 
      }, 
      token 
    });
  } catch (error) {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/api/users', authenticateToken, (req, res) => {
  try {
    const otherUsers = Array.from(users.values())
      .filter(u => u.id !== req.user.id)
      .map(({ password, socketId, ...user }) => user);
    
    res.json(otherUsers);
  } catch (error) {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/api/messages/:userId', authenticateToken, (req, res) => {
  try {
    const { userId } = req.params;
    const chatId = [req.user.id, userId].sort().join('_');
    
    const userMessages = messages.get(chatId) || [];
    res.json(userMessages);
  } catch (error) {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// WebSocket подключения
io.on('connection', (socket) => {
  console.log('Новый пользователь подключился:', socket.id);
  
  // Авторизация через сокет
  socket.on('authenticate', (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = users.get(decoded.id);
      
      if (user) {
        user.online = true;
        user.socketId = socket.id;
        users.set(user.id, user);
        
        socket.userId = user.id;
        
        // Оповещаем всех об изменении статуса
        io.emit('userStatus', {
          userId: user.id,
          online: true
        });
        
        console.log(`Пользователь ${user.name} авторизован`);
      }
    } catch (error) {
      console.log('Ошибка аутентификации:', error.message);
    }
  });
  
  // Отправка сообщения
  socket.on('sendMessage', (data) => {
    const { receiverId, text } = data;
    const senderId = socket.userId;
    
    if (!senderId || !receiverId) return;
    
    const chatId = [senderId, receiverId].sort().join('_');
    const message = {
      id: Date.now().toString(),
      senderId,
      receiverId,
      text,
      timestamp: new Date().toISOString(),
      read: false
    };
    
    // Сохраняем сообщение
    if (!messages.has(chatId)) {
      messages.set(chatId, []);
    }
    messages.get(chatId).push(message);
    
    // Отправляем получателю
    const receiver = Array.from(users.values()).find(u => u.id === receiverId);
    if (receiver && receiver.socketId) {
      io.to(receiver.socketId).emit('newMessage', message);
    }
    
    // Отправляем отправителю для подтверждения
    socket.emit('messageSent', message);
  });
  
  // Отметка сообщений как прочитанных
  socket.on('markAsRead', (data) => {
    const { senderId } = data;
    const receiverId = socket.userId;
    
    if (!senderId || !receiverId) return;
    
    const chatId = [senderId, receiverId].sort().join('_');
    const chatMessages = messages.get(chatId);
    
    if (chatMessages) {
      chatMessages.forEach(msg => {
        if (msg.senderId === senderId && msg.receiverId === receiverId) {
          msg.read = true;
        }
      });
    }
  });
  
  // Пользователь печатает
  socket.on('typing', (data) => {
    const { receiverId, isTyping } = data;
    const receiver = Array.from(users.values()).find(u => u.id === receiverId);
    
    if (receiver && receiver.socketId) {
      io.to(receiver.socketId).emit('userTyping', {
        senderId: socket.userId,
        isTyping
      });
    }
  });
  
  // Отключение пользователя
  socket.on('disconnect', () => {
    const user = Array.from(users.values()).find(u => u.socketId === socket.id);
    
    if (user) {
      user.online = false;
      user.socketId = null;
      users.set(user.id, user);
      
      io.emit('userStatus', {
        userId: user.id,
        online: false
      });
      
      console.log(`Пользователь ${user.name} отключился`);
    }
  });
});

// Старт сервера
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Сервер CKAM запущен на порту ${PORT}`);
  console.log(`Доступен по адресу: http://localhost:${PORT}`);
});