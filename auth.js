const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { prepare } = require("./db");

const JWT_SECRET = process.env.JWT_SECRET || "trustmesh-secret-change-in-production";

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Login required" });
  }

  try {
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    req.userRole = decoded.role;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Session expired, please login again" });
  }
}

function requireAdmin(req, res, next) {
  if (req.userRole !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}

function signup(req, res) {
  const { email, password, name } = req.body;

  if (!email || !password || !name) {
    return res.status(400).json({ error: "All fields are required" });
  }

  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  }

  const crypto = require("crypto");
  const existing = prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (existing) {
    return res.status(409).json({ error: "Email already registered" });
  }

  const id = crypto.randomUUID();
  const hashedPassword = bcrypt.hashSync(password, 10);

  // First user is admin
  const userCount = prepare("SELECT COUNT(*) as count FROM users").get();
  const role = userCount.count === 0 ? "admin" : "user";

  prepare("INSERT INTO users (id, email, password, name, role) VALUES (?, ?, ?, ?, ?)").run(id, email, hashedPassword, name, role);

  const token = jwt.sign({ userId: id, role }, JWT_SECRET, { expiresIn: "7d" });

  res.status(201).json({ token, user: { id, email, name, role } });
}

function login(req, res) {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const user = prepare("SELECT * FROM users WHERE email = ?").get(email);
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const valid = bcrypt.compareSync(password, user.password);
  if (!valid) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const token = jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET, { expiresIn: "7d" });

  res.json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
}

module.exports = { authenticate, requireAdmin, signup, login };
