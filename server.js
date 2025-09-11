import express from "express";
import bcrypt from "bcrypt";
import cors from "cors";
import jwt from "jsonwebtoken";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
//import pool from "./db.js";
import { authenticateToken } from "./middleware/auth.js";
import { PrismaClient } from "@prisma/client";
import dotenv from "dotenv";
import crypto from "crypto";
import nodemailer from "nodemailer";
import fs from "fs";
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const prisma = new PrismaClient();


// Config CORS
app.use(cors());

// Config para email (Nodemailer)
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER, // seu email
    pass: process.env.EMAIL_PASS, // senha ou App Password
  },
});



// Config pasta uploads
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// garante que a pasta uploads exista
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname),
});
const upload = multer({ storage });


// Middleware
app.use(express.json());
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use(express.urlencoded({ extended: true }));

// 📌 Rota de cadastro
// app.post("/api/signup", async (req, res) => {
//   try {
//     const { name, email, password } = req.body;
//     const hashedPass = await bcrypt.hash(password, 10);

//     const user = await prisma.user.create({
//       data: { name, email, password: hashedPass },
//       select: { id: true, name: true, email: true },
//     });

//     res.json({ message: "Usuário criado com sucesso", user });
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// 📌 Rota de cadastro
app.post("/api/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return res.status(400).json({ error: "Email already registered" });

    const hashedPass = await bcrypt.hash(password, 10);

    const verifyToken = crypto.randomBytes(32).toString("hex");

    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPass,
        verifyToken,
      },
    });

    const verifyUrl = `https://devimagehost.netlify.app/verify-email?token=${verifyToken}`;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Verify your account",
      html: `
        <h3>Welcome, ${name}!</h3>
        <p>Thanks for signing up. Please verify your email by clicking the link below:</p>
        <a href="${verifyUrl}">${verifyUrl}</a>
      `,
    });

    res.json({ message: "Account created successfully! Please check your email to verify your account." });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// 📌 Rota de verificação de email
app.get("/api/verify-email", async (req, res) => {
  try {
    const { token } = req.query;

    const user = await prisma.user.findFirst({ where: { verifyToken: token } });
    if (!user) return res.status(400).json({ error: "Invalid token" });

    await prisma.user.update({
      where: { id: user.id },
      data: { isVerified: true, verifyToken: null },
    });

    res.json({ message: "Email verified successfully! You can now log in." });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// 📌 Rota de login
// app.post("/api/login", async (req, res) => {
//   try {
//     const { email, password } = req.body;
//     const user = await prisma.user.findUnique({ where: { email } });

//     if (!user) return res.status(401).json({ error: "Usuário não encontrado" });

//     const validPass = await bcrypt.compare(password, user.password);
//     if (!validPass) return res.status(401).json({ error: "Senha incorreta" });

//     const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "1h" });

//     res.json({ message: "Login bem-sucedido", token });
//   } catch (err) {
//     res.status(500).json({ error: err.message });
//   }
// });

// 📌 Rota de login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(400).json({ error: "User not found" });

    if (!user.isVerified) {
      return res.status(403).json({ error: "Please verify your email before logging in." });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// 📌 Upload de imagem (protegida)
app.post("/api/upload", authenticateToken, upload.single("image"), async (req, res) => {
  try {
    const { file_type, dimensions } = req.body;
    // const fileUrl = `http://localhost:${PORT}/uploads/${req.file.filename}`;
    const fileUrl = `${process.env.BASE_URL || "https://devimagehost.netlify.app"}/uploads/${req.file.filename}`;


    const image = await prisma.image.create({
      data: {
        userId: req.user.id,
        filename: req.file.filename,
        fileUrl,
        fileType: file_type,
        dimensions,
      },
    });

    res.json({ message: "Imagem salva!", image });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// 📌 Listar imagens do usuário logado (revisado)
app.get("/api/my-images", authenticateToken, async (req, res) => {
  try {
    const images = await prisma.image.findMany({
      where: { userId: req.user.id },
      orderBy: { createdAt: "desc" },
      select: {
        id: true,
        filename: true,
        fileUrl: true,
        fileType: true,
        dimensions: true,
      },
    });

    res.json({ images });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// 📌 Deletar imagem
app.delete("/api/images/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const img = await prisma.image.findFirst({
      where: { id: Number(id), userId: req.user.id },
    });

    if (!img) return res.status(404).json({ error: "Imagem não encontrada ou não autorizada" });

    await prisma.image.delete({ where: { id: img.id } });

    res.json({ message: "Imagem deletada com sucesso!" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});



// 📌 Atualizar nome do arquivo (somente nome, mantendo extensão)
app.put("/api/images/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { newFilename } = req.body;

    if (!newFilename || newFilename.trim() === "") {
      return res.status(400).json({ error: "Novo nome não pode ser vazio" });
    }

    // Busca a imagem
    const image = await prisma.image.findFirst({
      where: { id: Number(id), userId: req.user.id },
    });

    if (!image) {
      return res.status(404).json({ error: "Imagem não encontrada ou não autorizada" });
    }

    // Extrai extensão original
    const ext = path.extname(image.filename); // exemplo: ".png"
    const safeName = newFilename.replace(/\.[^/.]+$/, ""); // remove extensão se usuário digitou

    const finalFilename = safeName + ext;

    const oldPath = path.join(__dirname, "uploads", image.filename);
    const newPath = path.join(__dirname, "uploads", finalFilename);

    // Se já existir arquivo com o mesmo nome, retorna erro
    if (fs.existsSync(newPath)) {
      return res.status(400).json({ error: "Já existe um arquivo com esse nome" });
    }

    // Renomeia fisicamente
    fs.renameSync(oldPath, newPath);

    // Atualiza banco
    const updated = await prisma.image.update({
      where: { id: image.id },
      data: {
        filename: finalFilename,
        fileUrl: `https://devimagehost.netlify.app/uploads/${finalFilename}`,
      },
    });

    res.json({ message: "Arquivo renomeado com sucesso!", image: updated });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});



// 📌 Atualizar dados da conta
app.put("/api/account", authenticateToken, async (req, res) => {
  try {
    const { name, email } = req.body;

    const user = await prisma.user.update({
      where: { id: req.user.id },
      data: { name, email },
      select: { id: true, name: true, email: true },
    });

    res.json({ message: "Conta atualizada com sucesso", user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 📌 Obter dados da conta logada
app.get("/api/account", authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: { id: true, name: true, email: true },
    });

    if (!user) return res.status(404).json({ error: "Usuário não encontrado" });

    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 📌 Alterar senha
app.put("/api/account/password", authenticateToken, async (req, res) => {
  try {
    const { current, newPass } = req.body;

    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    const validPass = await bcrypt.compare(current, user.password);
    if (!validPass) return res.status(401).json({ error: "Senha atual incorreta" });

    const hashedPass = await bcrypt.hash(newPass, 10);

    await prisma.user.update({
      where: { id: req.user.id },
      data: { password: hashedPass },
    });

    res.json({ message: "Senha alterada com sucesso" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// 📌 Solicitar reset de senha
app.post("/api/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ error: "User not found" });

    // gera token único
    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenExpiry = new Date(Date.now() + 1000 * 60 * 15); // expira em 15 min

    await prisma.user.update({
      where: { id: user.id },
      data: {
        resetToken,
        resetTokenExpiry,
      },
    });

    const resetUrl = `https://devimagehost.netlify.app/reset-password?token=${resetToken}`;

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Password Reset Request",
      html: `
        <p>You requested a password reset.</p>
        <p>Click the link below to reset your password:</p>
        <a href="${resetUrl}">${resetUrl}</a>
        <p>This link expires in 15 minutes.</p>
      `,
    });

    res.json({ message: "Password reset email sent" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// 📌 Resetar senha com token
app.post("/api/reset-password", async (req, res) => {
  try {
    const { token, newPass } = req.body;

    const user = await prisma.user.findFirst({
      where: {
        resetToken: token,
        resetTokenExpiry: { gte: new Date() }, // token ainda válido
      },
    });

    if (!user) return res.status(400).json({ error: "Invalid or expired token" });

    const hashedPass = await bcrypt.hash(newPass, 10);

    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPass,
        resetToken: null,
        resetTokenExpiry: null,
      },
    });

    res.json({ message: "Password reset successful" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// 📌 Rota de contato
app.post("/api/contact", async (req, res) => {
  try {
    console.log("Body recebido:", req.body); // 👈 debug
    const { c_name, c_email, c_message } = req.body;

    if (!c_name || !c_email || !c_message) {
      return res.status(400).json({ error: "Todos os campos são obrigatórios" });
    }

    // Email para você
    await transporter.sendMail({
      from: `"DevImageHost Contact" <${process.env.EMAIL_USER}>`,
      to: "sejoaovb@gmail.com",
      subject: "📩 Nova mensagem de contato",
      text: `De: ${c_name} <${c_email}>\n\n${c_message}`,
      html: `<p><b>Nome:</b> ${c_name}</p>
             <p><b>Email:</b> ${c_email}</p>
             <p><b>Mensagem:</b></p>
             <p>${c_message}</p>`,
    });

    res.json({ message: "Mensagem enviada com sucesso!" });
  } catch (err) {
    console.error("Erro ao enviar email:", err);
    res.status(500).json({ error: "Erro ao enviar a mensagem. Tente novamente." });
  }
});



// Inicia servidor
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));

export default app;
