import express from "express";
import { readJSON, writeJSON } from "../utils/fileDb.js";
import { requireAuth, requireRole } from "../middleware/auth.js";
import bcrypt from "bcryptjs";

const router = express.Router();
const file = "./data/users.json";

// Получить всех пользователей (только админ)
router.get("/all", requireAuth, requireRole("admin"), async (req, res) => {
  const users = await readJSON(file);
  res.json(users);
});

// Получить одного пользователя по id
router.get("/:id", requireAuth, async (req, res) => {
  const users = await readJSON(file);
  const user = users.find((u) => u.id == req.params.id);
  if (!user) return res.sendStatus(404);
  res.json(user);
});

// Пагинация (для админа)
router.get("/", requireAuth, requireRole("admin"), async (req, res) => {
  const users = await readJSON(file);
  const pageNum = parseInt(req.query.page) || 1;
  const limitNum = parseInt(req.query.limit) || 10;
  const totalItems = users.length;
  const totalPages = Math.ceil(totalItems / limitNum);
  const startIdx = (pageNum - 1) * limitNum;
  const endIdx = startIdx + limitNum;
  const items = users.slice(startIdx, endIdx);
  res.json({
    items,
    page: pageNum,
    limit: limitNum,
    totalItems,
    totalPages,
  });
});

// ------------------ CRUD для админа ------------------

// Добавить нового пользователя
router.post("/", requireAuth, requireRole("admin"), async (req, res) => {
  const users = await readJSON(file);
  const { name, email, password, role } = req.body;

  if (!name || !email) {
    return res.status(400).json({ message: "Name и Email обязательны" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = {
    id: Date.now(), // простой генератор id
    name,
    email,
    password: hashedPassword,
    role: role || "user",
  };

  users.push(newUser);
  await writeJSON(file, users);

  res.status(201).json(newUser);
});

// Редактировать пользователя
router.put("/:id", requireAuth, requireRole("admin"), async (req, res) => {
  const users = await readJSON(file);
  const idx = users.findIndex((u) => u.id == req.params.id);

  if (idx === -1) {
    return res.status(404).json({ message: "Пользователь не найден" });
  }

  const { name, email, password, role } = req.body;
  users[idx] = {
    ...users[idx],
    name: name ?? users[idx].name,
    email: email ?? users[idx].email,
    password: password ? await bcrypt.hash(password, 10) : users[idx].password,
    role: role ?? users[idx].role,
  };

  await writeJSON(file, users);
  res.json(users[idx]);
});

// Удалить пользователя
router.delete("/:id", requireAuth, requireRole("admin"), async (req, res) => {
  const users = await readJSON(file);
  const idx = users.findIndex((u) => u.id == req.params.id);

  if (idx === -1) {
    return res.status(404).json({ message: "Пользователь не найден" });
  }

  const deleted = users.splice(idx, 1)[0];
  await writeJSON(file, users);

  res.json(deleted);
});

export default router;
