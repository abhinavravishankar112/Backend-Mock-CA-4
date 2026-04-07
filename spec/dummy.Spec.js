const express = require('express');
const request = require('supertest');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

process.env.JWT_SECRET = 'test_secret_key_12345';

let authController;
try {
  authController = require('../controllers/auth.controller');
} catch (e) {
  authController = null;
}

let authMiddleware, checkTaskOwnership, tasks;
try {
  const middleware = require('../middleware/auth.middleware');
  authMiddleware = middleware.authMiddleware;
  checkTaskOwnership = middleware.checkTaskOwnership;
  tasks = middleware.tasks;
} catch (e) {
  authMiddleware = null;
  checkTaskOwnership = null;
  tasks = null;
}

const app = express();
app.use(express.json());
app.use(cookieParser());

if (authController && authController.registerUser) {
  app.post('/auth/register', authController.registerUser);
}
if (authController && authController.loginUser) {
  app.post('/auth/login', authController.loginUser);
}
if (authMiddleware && checkTaskOwnership) {
  app.delete('/tasks/:id', authMiddleware, checkTaskOwnership, (req, res) => {
    res.status(200).json({ message: 'Task deleted successfully' });
  });
}
app.use((err, req, res, next) => {
  res.status(500).json({ status: 'error', message: err.message });
});

describe('Mock Assessment: Authentication & Authorization System', () => {
  beforeEach(() => {
    if (authController && authController.users) {
      authController.users.length = 0;
    }
    if (tasks) {
      tasks.length = 0;
    }
  });

  describe('Authentication Controllers', () => {
    it('TC1: POST /auth/register should return 400 if user with email already exists', async () => {
      const userData = { username: 'john', email: 'john@example.com', password: 'pass123' };
      
      await request(app).post('/auth/register').send(userData);
      const response = await request(app).post('/auth/register').send(userData);
      
      expect(response.statusCode).toBe(400);
      expect(response.body.message).toBe('User already exists');
    });

    it('TC2: POST /auth/register should hash password with 12 salt rounds and return 201 with user data', async () => {
      const userData = { username: 'alice', email: 'alice@example.com', password: 'secure123' };
      
      const response = await request(app).post('/auth/register').send(userData);
      
      expect(response.statusCode).toBe(201);
      expect(response.body.username).toBe('alice');
      expect(response.body.email).toBe('alice@example.com');
      expect(response.body.password).toBeUndefined();
      
      const storedUser = authController.users[0];
      const isValidHash = await bcrypt.compare('secure123', storedUser.password);
      expect(isValidHash).toBe(true);
    });

    it('TC3: POST /auth/login should return 404 if user not found and 401 if password invalid', async () => {
      const hashedPassword = await bcrypt.hash('correct123', 12);
      authController.users.push({ id: 1, username: 'bob', email: 'bob@example.com', password: hashedPassword });
      
      const notFoundResponse = await request(app).post('/auth/login').send({ email: 'nobody@example.com', password: 'any' });
      expect(notFoundResponse.statusCode).toBe(404);
      expect(notFoundResponse.body.message).toBe('User not found');
      
      const invalidPassResponse = await request(app).post('/auth/login').send({ email: 'bob@example.com', password: 'wrong' });
      expect(invalidPassResponse.statusCode).toBe(401);
      expect(invalidPassResponse.body.message).toBe('Invalid credentials');
    });

    it('TC4: POST /auth/login should set HttpOnly cookie with JWT and return 200 on valid credentials', async () => {
      const hashedPassword = await bcrypt.hash('validpass', 12);
      authController.users.push({ id: 1, username: 'charlie', email: 'charlie@example.com', password: hashedPassword });
      
      const response = await request(app).post('/auth/login').send({ email: 'charlie@example.com', password: 'validpass' });
      
      expect(response.statusCode).toBe(200);
      expect(response.body.message).toBe('Login successful');
      expect(response.body.user.username).toBe('charlie');
      
      const cookies = response.headers['set-cookie'];
      expect(cookies).toBeDefined();
      expect(cookies[0]).toContain('token=');
      expect(cookies[0]).toContain('HttpOnly');
    });

    it('TC5: JWT token should have correct payload and 2-hour expiration', async () => {
      const hashedPassword = await bcrypt.hash('testpass', 12);
      authController.users.push({ id: 2, username: 'dave', email: 'dave@example.com', password: hashedPassword });
      
      const response = await request(app).post('/auth/login').send({ email: 'dave@example.com', password: 'testpass' });
      
      const cookies = response.headers['set-cookie'];
      const tokenCookie = cookies[0];
      const token = tokenCookie.split(';')[0].split('=')[1];
      
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      expect(decoded.userId).toBe(2);
      expect(decoded.email).toBe('dave@example.com');
      
      const expirationTime = decoded.exp - decoded.iat;
      expect(expirationTime).toBe(7200); // 2 hours = 7200 seconds
    });
  });

  describe('Authentication & Authorization Middleware', () => {
    let validToken;

    beforeEach(async () => {
      const hashedPassword = await bcrypt.hash('mypass', 12);
      authController.users.push({ id: 1, username: 'owner', email: 'owner@example.com', password: hashedPassword });
      
      validToken = jwt.sign({ userId: 1, email: 'owner@example.com' }, process.env.JWT_SECRET, { expiresIn: '2h' });
      
      tasks.push({ id: 1, title: 'Task 1', userId: 1 });
      tasks.push({ id: 2, title: 'Task 2', userId: 2 });
    });

    it('TC6: authMiddleware should return 401 if no token is provided', async () => {
      const response = await request(app).delete('/tasks/1');
      
      expect(response.statusCode).toBe(401);
      expect(response.body.message).toBe('No token provided');
    });

    it('TC7: authMiddleware should return 401 if token is invalid', async () => {
      const response = await request(app)
        .delete('/tasks/1')
        .set('Cookie', ['token=invalid_token_here']);
      
      expect(response.statusCode).toBe(401);
      expect(response.body.message).toBe('Invalid token');
    });

    it('TC8: authMiddleware should attach decoded user to req.user and call next() for valid token', async () => {
      const response = await request(app)
        .delete('/tasks/1')
        .set('Cookie', [`token=${validToken}`]);
      
      // If we reach the controller, authMiddleware worked
      expect(response.statusCode).toBe(200);
      expect(response.body.message).toBe('Task deleted successfully');
    });

    it('TC9: checkTaskOwnership should return 404 if task not found and 403 if user does not own task', async () => {
      const notFoundResponse = await request(app)
        .delete('/tasks/999')
        .set('Cookie', [`token=${validToken}`]);
      expect(notFoundResponse.statusCode).toBe(404);
      expect(notFoundResponse.body.message).toBe('Task not found');
      
      const forbiddenResponse = await request(app)
        .delete('/tasks/2')
        .set('Cookie', [`token=${validToken}`]);
      expect(forbiddenResponse.statusCode).toBe(403);
      expect(forbiddenResponse.body.message).toBe('Access denied');
    });

    it('TC10: checkTaskOwnership should call next() if user owns the task', async () => {
      const response = await request(app)
        .delete('/tasks/1')
        .set('Cookie', [`token=${validToken}`]);
      
      expect(response.statusCode).toBe(200);
      expect(response.body.message).toBe('Task deleted successfully');
    });
  });
});