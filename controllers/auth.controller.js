const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Mock database
const users = [];

/**
 * TODO: Implement registerUser.
 * - Extract username, email, password from req.body.
 * - Check if user with email already exists. If yes, return 400 with { message: 'User already exists' }.
 * - Hash password with bcrypt (12 salt rounds).
 * - Create user: { id: users.length + 1, username, email, password: hashedPassword }.
 * - Add to users array.
 * - Respond with 201 and { id, username, email }.
 * - Use try...catch, pass errors to next().
 */
const registerUser = async (req, res, next) => {
  try {
    const { username, email, password } = req.body;
    const existingUser = users.find((user) => user.email === email);
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = {
      id: users.length + 1,
      username,
      email,
      password: hashedPassword,
    };
    users.push(newUser);
    res.status(201).json({
      id: newUser.id,
      username: newUser.username,
      email: newUser.email,
    });
  } catch (error) {
    next(error);
  }
};

/**
 * TODO: Implement loginUser.
 * - Extract email, password from req.body.
 * - Find user by email. If not found, return 404 with { message: 'User not found' }.
 * - Verify password with bcrypt.compare(). If invalid, return 401 with { message: 'Invalid credentials' }.
 * - Generate JWT: payload { userId: user.id, email: user.email }, secret process.env.JWT_SECRET, expiration '2h'.
 * - Set token in HttpOnly cookie named 'token' with { httpOnly: true, maxAge: 7200000 }.
 * - Respond with 200 and { message: 'Login successful', user: { id, username, email } }.
 * - Use try...catch, pass errors to next().
 */
const loginUser = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = users.find((u) => u.email === email);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '2h' }
    );
    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 7200000,
    });
    res.status(200).json({
      message: 'Login successful',
      user: { id: user.id, username: user.username, email: user.email },
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  registerUser,
  loginUser,
  users,
};
