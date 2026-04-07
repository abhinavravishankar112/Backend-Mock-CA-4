const jwt = require('jsonwebtoken');

// Mock tasks database
const tasks = [];

const authMiddleware = (req, res, next) => {
  try {
    const token = req.cookies.token;

    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded;
    next();

  } catch (error) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

const checkTaskOwnership = (req, res, next) => {
  const taskId = Number(req.params.id);

  const task = tasks.find(t => t.id === taskId);

  if (!task) {
    return res.status(404).json({ message: 'Task not found' });
  }

  if (task.userId !== req.user.userId) {
    return res.status(403).json({ message: 'Access denied' });
  }

  next();
};

module.exports = {
  authMiddleware,
  checkTaskOwnership,
  tasks,
};