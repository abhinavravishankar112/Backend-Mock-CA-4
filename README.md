## Problem Statement

Your task is to build a complete authentication and authorization system with user registration, login with JWT cookies, authentication middleware, and resource ownership verification. This assessment tests your understanding of secure password hashing, JWT-based authentication, cookies, and authorization logic.

### Part 1: Authentication Controllers (`controllers/auth.controller.js`)

**`registerUser` Requirements:**
- Check if user exists. If yes, return **400** with `{ message: 'User already exists' }`.
- Hash password with bcrypt using **12 salt rounds**.
- Create and store user: `{ id, username, email, password: hashedPassword }`.
- Return **201** with `{ id, username, email }`.

**`loginUser` Requirements:**
- Find user by email. If not found, return **404** with `{ message: 'User not found' }`.
- Verify password. If invalid, return **401** with `{ message: 'Invalid credentials' }`.
- Generate JWT with payload `{ userId, email }`, expiration `'2h'`.
- Set HttpOnly cookie named `'token'` with `{ httpOnly: true, maxAge: 7200000 }`.
- Return **200** with `{ message: 'Login successful', user: { id, username, email } }`.

### Part 2: Middleware (`middleware/auth.middleware.js`)

**`authMiddleware` Requirements:**
- Extract token from `req.cookies.token`.
- If no token, return **401** with `{ message: 'No token provided' }`.
- Verify token. If invalid, return **401** with `{ message: 'Invalid token' }`.
- Attach decoded payload to `req.user` and call `next()`.

**`checkTaskOwnership` Requirements:**
- Extract `taskId` from `req.params.id`.
- Find task. If not found, return **404** with `{ message: 'Task not found' }`.
- Compare `task.userId` with `req.user.userId`.
- If don't match, return **403** with `{ message: 'Access denied' }`.
- If match, call `next()`.

## How to Test Your Solution

1. Run `npm test`.
2. All tests verify password hashing, JWT generation, cookie settings, middleware logic, and authorization checks.
3. Your solution is complete when the output shows **`10 specs, 0 failures`**.

## Key Concepts Tested

- Duplicate user detection
- Secure password hashing with 12 salt rounds
- JWT generation with 2-hour expiration
- Setting HttpOnly cookies for JWT storage
- Authentication middleware to verify tokens
- Authorization middleware to check resource ownership
- Proper HTTP status codes (400, 401, 403, 404)

This assessment is harder than the final because it requires:
- Duplicate user checking
- Higher salt rounds (12 vs 10)
- JWT in cookies instead of response body
- Two middleware functions (authentication + authorization)
- Resource ownership verification

Good luck!