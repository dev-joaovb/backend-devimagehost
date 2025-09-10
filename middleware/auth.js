import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();


const JWT_SECRET = process.env.JWT_SECRET; // ⚠️ depois mova para variável de ambiente

export function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ error: "Token não fornecido" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Token inválido ou expirado" });
    req.user = user; // user.id está disponível
    next();
  });
}