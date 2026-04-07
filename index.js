const express = require('express');
const cookieParser = require('cookie-parser');
const authController = require('./controllers/auth.controller');
const { authMiddleware, checkTaskOwnership } = require('./middleware/auth.middleware');

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

module.exports = app;