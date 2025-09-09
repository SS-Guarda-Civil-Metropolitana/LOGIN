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

// Configuração CORS única e correta, permitindo apenas a URL do seu site na Vercel
app.use(cors({
  origin: 'https://login-xi-smoky.vercel.app' // Substitua pela sua URL Vercel
}));

// Middlewares
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

// Configuração de Conexão com o Banco de Dados (usando variáveis de ambiente do Railway)
const dbConfig = {
    host: process.env.MYSQL_HOST,
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE
};

// Conexão com o banco de dados
const connection = mysql.createConnection(dbConfig);


// ROTAS DA API
// Rota de Cadastro de Usuários
app.post('/cadastrar', async (req, res) => {
    const { nomeCompleto, nomeGuerra, cpf, email, matricula, senha, nivelAcesso } = req.body;
    // ... (O resto do seu código de cadastro)
    // ... (Seu código de cadastro não foi alterado pois ele já estava correto)
});

// Rota de LOGIN
app.post('/api/login', async (req, res) => {
    const { username, password, tipoAcesso } = req.body;
    // ... (O resto do seu código de login)
    // ... (Seu código de login não foi alterado pois ele já estava correto)
});

// Rotas Protegidas por Nível de Acesso
app.get('/api/acesso-operacional', authenticateToken, authorizeRoles(['Operacional', 'Tatico', 'Estrategico']), (req, res) => {
    res.status(200).json({ message: `Bem-vindo, ${req.user.username}! Você tem acesso ao nível Operacional. Seu nível: ${req.user.nivelAcesso}.`, seuNivel: req.user.nivelAcesso });
});
app.get('/api/acesso-tatico', authenticateToken, authorizeRoles(['Tatico', 'Estrategico']), (req, res) => {
    res.status(200).json({ message: `Bem-vindo, ${req.user.username}! Você tem acesso ao nível Tático. Seu nível: ${req.user.nivelAcesso}.`, seuNivel: req.user.nivelAcesso });
});
app.get('/api/acesso-estrategico', authenticateToken, authorizeRoles(['Estrategico']), (req, res) => {
    res.status(200).json({ message: `Bem-vindo, ${req.user.username}! Você tem acesso ao nível Estratégico. Seu nível: ${req.user.nivelAcesso}.`, seuNivel: req.user.nivelAcesso });
});

// Rota para cadastrar morador
app.post('/api/moradores', upload.single('imagen'), async (req, res) => {
    try {
        const connection = await mysql.createConnection(dbConfig);
        const { nomeCompleto, vulgo, antecedentes, vicios, nomeMae, cpf, rg, endereco, naturalidade, informacao, bolsafamilia, registropop, registropsocial, entradacaps } = req.body;
        const imagen = req.file ? req.file.filename : null;

        if (!nomeCompleto || !cpf) {
            await connection.end();
            return res.status(400).json({ success: false, message: 'Nome completo e CPF são campos obrigatórios.' });
        }

        const query = `
            INSERT INTO morador_rua (
                nomeCompleto, vulgo, antecedentes, vicios, nome_mae, cpf, rg, endereco, naturalidade, informacao,
                bolsafamilia, registropop, registropsocial, entradacaps, imagen
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        const [results] = await connection.execute(query, [
            nomeCompleto, vulgo || null, antecedentes || null, vicios || null, nomeMae || null,
            cpf, rg || null, endereco || null, naturalidade || null, informacao || '',
            bolsafamilia || '', registropop || '', registropsocial || '', entradacaps || null, imagen
        ]);
        await connection.end();

        res.status(201).json({
            success: true,
            message: 'Morador cadastrado com sucesso!',
            id: results.insertId
        });
    } catch (error) {
        console.error('Erro ao cadastrar morador:', error);
        if (connection) await connection.end();
        res.status(500).json({
            success: false,
            message: 'Erro interno do servidor ao cadastrar o morador.',
            error: error.message
        });
    }
});

app.get('/api/caps', authenticateToken, authorizeRoles(['caps', 'sim', 'nao']), (req, res) => {
    res.status(200).json({ message: `Bem-vindo, ${req.user.username}! Você tem acesso ao nível Operacional. Seu nível: ${req.user.entradacaps}.`, seucaps: req.user.entradacaps });
});
app.get('/api/sim', authenticateToken, authorizeRoles(['sim', 'nao']), (req, res) => {
    res.status(200).json({ message: `Bem-vindo, ${req.user.username}! Você tem acesso ao nível Tático. Seu nível: ${req.user.entradacaps}.`, seucaps: req.user.entradacaps });
});
app.get('/api/nao', authenticateToken, authorizeRoles(['nao']), (req, res) => {
    res.status(200).json({ message: `Bem-vindo, ${req.user.username}! Você tem acesso ao nível Estratégico. Seu nível: ${req.user.entradacaps}.`, seucaps: req.user.entradacaps });
});

// Rota de busca por morador de rua
app.get('/api/moradores/busca', authenticateToken, async (req, res) => {
    const { nomeCompleto, cpf, rg } = req.query;

    if (!nomeCompleto && !cpf && !rg) {
        return res.status(400).json({ success: false, message: 'Pelo menos um critério de busca (nome, cpf ou rg) é obrigatório.' });
    }

    let connection;
    try {
        connection = await mysql.createConnection(dbConfig);
        let query = `
            SELECT id, nomeCompleto, cpf, nome_mae, vulgo, informacao, antecedentes,
            registropop, entradacaps, registropsocial, naturalidade, endereco, bolsafamilia, imagen
            FROM morador_rua
            WHERE 1=1
        `;
        const params = [];

        if (nomeCompleto) {
            query += ` AND nomeCompleto LIKE ?`;
            params.push(`%${nomeCompleto}%`);
        }

        if (cpf) {
            query += ` AND cpf = ?`;
            params.push(cpf);
        }

        if (rg) {
            query += ` AND rg = ?`;
            params.push(rg);
        }

        const [rows] = await connection.execute(query, params);
        await connection.end();

        res.status(200).json({ success: true, moradores: rows });
    } catch (error) {
        console.error('ERRO NA BUSCA (CATCH):', error);
        if (connection) await connection.end();
        res.status(500).json({ success: false, message: 'Erro interno do servidor durante a busca.' });
    }
});

// Rota para buscar um morador por ID
app.get('/api/moradores/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;

    if (!id) {
        return res.status(400).json({ success: false, message: 'ID do morador é obrigatório.' });
    }

    let connection;
    try {
        connection = await mysql.createConnection(dbConfig);
        const query = `
            SELECT * FROM morador_rua WHERE id = ?
        `;
        const [rows] = await connection.execute(query, [id]);
        await connection.end();

        if (rows.length > 0) {
            res.status(200).json({ success: true, morador: rows[0] });
        } else {
            res.status(404).json({ success: false, message: 'Morador não encontrado.' });
        }
    } catch (error) {
        console.error('ERRO NA BUSCA POR ID (CATCH):', error);
        if (connection) await connection.end();
        res.status(500).json({ success: false, message: 'Erro interno do servidor.' });
    }
});

// Inicia o Servidor (somente uma vez!)
app.listen(port, () => {
    console.log(`Servidor Node.js rodando na porta ${port}`);
    console.log(`API acessível em ${process.env.PUBLIC_URL}`);
});