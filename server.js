require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const prisma = require('@prisma/client').PrismaClient;
const prismaClient = new prisma();

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;

app.post(
  '/register',
  [
    body('name').notEmpty().withMessage('El nombre es requerido'),
    body('email').isEmail().withMessage('Correo con formato invalido'),
    body('password')
    .isLength({ min: 8 }).withMessage('La contraseña debe tener al menos 8 caracteres')
    .matches(/(?=.*[A-Z])/, 'g').withMessage('La contraseña debe tener al menos una letra mayúscula')
    .matches(/(?=.*\d)/, 'g').withMessage('La contraseña debe tener al menos un número'),
  ],
  async (req, res) => {

    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { name, email, password } = req.body;

    const existingUser = await prismaClient.user.findUnique({
      where: { email }
    });

    if (existingUser) {
      return res.status(400).json({ message: 'Ya existe un usuario registrado con ese correo' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await prismaClient.user.create({
      data: {
        name,
        email,
        password: hashedPassword
      }
    });

    return res.status(201).json({ message: 'Usuario dado de alta correctamente', user: { id: newUser.id, name: newUser.name, email: newUser.email } });
  }
);

app.post(
  '/login',
  [
    body('email').isEmail().withMessage('Correo con formato inválido'),
    body('password').notEmpty().withMessage('La contraseña es requerido'),
  ],
  async (req, res) => {

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    const user = await prismaClient.user.findUnique({
      where: { email }
    });

    if (!user) {
      return res.status(400).json({ message: 'Credenciales incorrectas' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Credenciales incorrectas' });
    }

    const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

    return res.json({ message: 'Login exitoso', token });
  }
);

const authMiddleware = (req, res, next) => {

  const token = req.header('Authorization')?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ message: 'Se necesita autorización' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; 
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Token inválido o expirado' });
  }
};

app.get('/profile', authMiddleware, async (req, res) => {

  const user = await prismaClient.user.findUnique({
    select: {  
        id: true,
        name: true,
        email: true,
        createdAt: true,
    },
    where: { id: req.user.id },
  });

  if (!user) {
    return res.status(404).json({ message: 'Usuario no encontrado' });
  }

  res.json({ message: 'Bienvenido a su perfil', user });
});

const port = 3000;
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
