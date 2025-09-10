const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const cors = require('cors');
require('dotenv').config();
const multer = require('multer');
const path = require('path');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 8080;

// ✅ CORREÇÃO: Configuração CORS para múltiplas origens
app.use(cors({
  origin: [
    'https://login-xi-smoky.vercel.app',
    'http://localhost:3001',
    'http://localhost:3000'
  ],
  credentials: true
}));

// Middlewares
app.use(express.static('public'));
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'sua_chave_secreta_muito_segura_e_longa_aqui';

// ✅ CORREÇÃO: Configuração única e correta da conexão
const dbConfig = {
    host: process.env.MYSQLHOST,
    user: process.env.MYSQLUSER,
    password: process.env.MYSQLPASSWORD,
    database: process.env.MYSQLDATABASE,
    port: process.env.MYSQLPORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

// ✅ Cria pool de conexões
const pool = mysql.createPool(dbConfig);

// Middleware de Autenticação
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Acesso negado. Token não fornecido.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Token inválido ou expirado.' });
        }
        req.user = user;
        next();
    });
};

// ... (o restante do código permanece igual)

// Rota de saúde para teste
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'OK', 
        message: 'Servidor está funcionando',
        timestamp: new Date().toISOString()
    });
});

// Inicia o Servidor
app.listen(port, () => {
    console.log(`Servidor Node.js rodando na porta ${port}`);
    console.log('Conectado ao banco de dados MySQL no Railway');
});