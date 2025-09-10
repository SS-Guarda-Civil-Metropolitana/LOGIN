const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const cors = require('cors');
require('dotenv').config();
const multer = require('multer');
const path = require('path');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 8000;

app.use(cors({
  origin: 'https://login-xi-smoky.vercel.app'
}));

app.use(express.static('public'));
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'sua_chave_secreta_muito_segura_e_longa_aqui';

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

// Middleware de Autorização por Nível de Acesso
const authorizeRoles = (allowedRoles) => {
    return (req, res, next) => {
        if (!req.user || !req.user.nivelAcesso || req.user.entradacaps) {
            return res.status(403).json({ message: 'Acesso negado. Nível de acesso não definido no token.' });
        }

        const userRole = req.user.nivelAcesso || req.user.entradacaps;
        if (allowedRoles.includes(userRole)) {
            next();
        } else {
            return res.status(403).json({ message: `Acesso negado. Você não tem permissão para esta operação. Seu nível: ${userRole}.` });
        }
    };
};

// Configuração do Multer para upload de imagens
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'public/uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage: storage });

// ROTAS DA API
// Rota de Cadastro de Usuários
app.post('/cadastrar', async (req, res) => {
    const { nomeCompleto, nomeGuerra, cpf, email, matricula, senha, nivelAcesso } = req.body;
    
    let connection;
    try {
        connection = await mysql.createConnection(process.env.MYSQL_URL); // Conexão corrigida
        // ... (O resto do seu código de cadastro)
    } catch (error) {
        // ... (Seu código de catch)
    }
});

// Rota de LOGIN
app.post('/api/login', async (req, res) => {
    const { username, password, tipoAcesso } = req.body;
    
    let connection;
    try {
        connection = await mysql.createConnection(process.env.MYSQL_URL); // Conexão corrigida
        // ... (O resto do seu código de login)
    } catch (error) {
        // ... (Seu código de catch)
    }
});

// Outras rotas da API...
app.post('/api/moradores', upload.single('imagen'), async (req, res) => {
    let connection;
    try {
        connection = await mysql.createConnection(process.env.MYSQL_URL); // Conexão corrigida
        // ... (Seu código da rota)
    } catch (error) {
        // ... (Seu código de catch)
    }
});

app.get('/api/moradores/busca', authenticateToken, async (req, res) => {
    let connection;
    try {
        connection = await mysql.createConnection(process.env.MYSQL_URL); // Conexão corrigida
        // ... (Seu código da rota)
    } catch (error) {
        // ... (Seu código de catch)
    }
});

app.get('/api/moradores/:id', authenticateToken, async (req, res) => {
    let connection;
    try {
        connection = await mysql.createConnection(process.env.MYSQL_URL); // Conexão corrigida
        // ... (Seu código da rota)
    } catch (error) {
        // ... (Seu código de catch)
    }
});


// ... (As outras rotas de autenticação também precisam ser corrigidas)


// Inicia o Servidor
app.listen(port, () => {
    console.log(`Servidor Node.js rodando na porta ${port}`);
});