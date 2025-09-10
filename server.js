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

// Configuração CORS
app.use(cors({
  origin: 'https://login-xi-smoky.vercel.app'
}));

// Middlewares
app.use(express.static('public'));
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'sua_chave_secreta_muito_segura_e_longa_aqui';

// ✅ CORREÇÃO: Configuração única e correta da conexão
const dbConfig = {
    host: process.env.MYSQLHOST, // Railway usa MYSQLHOST (sem underscore)
    user: process.env.MYSQLUSER, // MYSQLUSER (sem underscore)
    password: process.env.MYSQLPASSWORD, // MYSQLPASSWORD (sem underscore)
    database: process.env.MYSQLDATABASE, // MYSQLDATABASE (sem underscore)
    port: process.env.MYSQLPORT || 3306, // MYSQLPORT (sem underscore)
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

// ✅ Cria pool de conexões (mais eficiente)
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

// Middleware de Autorização por Nível de Acesso
const authorizeRoles = (allowedRoles) => {
    return (req, res, next) => {
        if (!req.user || (!req.user.nivelAcesso && !req.user.entradacaps)) {
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

// Configuração do Multer
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
    
    try {
        // Validações básicas
        if (!nomeCompleto || !nomeGuerra || !cpf || !email || !matricula || !senha || !nivelAcesso) {
            return res.status(400).json({ success: false, message: 'Todos os campos são obrigatórios.' });
        }

        // Verifica se usuário já existe
        const [existingUsers] = await pool.execute(
            'SELECT id FROM usuarios WHERE email = ? OR cpf = ? OR matricula = ?',
            [email, cpf, matricula]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({ success: false, message: 'Usuário já cadastrado com este email, CPF ou matrícula.' });
        }

        // Hash da senha
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(senha, saltRounds);

        // Insere usuário
        const [result] = await pool.execute(
            'INSERT INTO usuarios (nomeCompleto, nomeGuerra, cpf, email, matricula, senha, nivelAcesso) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [nomeCompleto, nomeGuerra, cpf, email, matricula, hashedPassword, nivelAcesso]
        );

        res.status(201).json({
            success: true,
            message: 'Usuário cadastrado com sucesso!',
            userId: result.insertId
        });

    } catch (error) {
        console.error('Erro ao cadastrar usuário:', error);
        res.status(500).json({
            success: false,
            message: 'Erro interno do servidor ao cadastrar usuário.',
            error: error.message
        });
    }
});

// Rota de LOGIN
app.post('/api/login', async (req, res) => {
    const { username, password, tipoAcesso } = req.body;

    try {
        if (!username || !password) {
            return res.status(400).json({ success: false, message: 'Email/CPF/Matrícula e senha são obrigatórios.' });
        }

        // Busca usuário por email, CPF ou matrícula
        const [users] = await pool.execute(
            'SELECT * FROM usuarios WHERE email = ? OR cpf = ? OR matricula = ?',
            [username, username, username]
        );

        if (users.length === 0) {
            return res.status(401).json({ success: false, message: 'Credenciais inválidas.' });
        }

        const user = users[0];

        // Verifica senha
        const isPasswordValid = await bcrypt.compare(password, user.senha);
        if (!isPasswordValid) {
            return res.status(401).json({ success: false, message: 'Credenciais inválidas.' });
        }

        // Gera token JWT
        const token = jwt.sign(
            { 
                id: user.id, 
                username: user.nomeGuerra, 
                nivelAcesso: user.nivelAcesso,
                entradacaps: user.entradacaps 
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            message: 'Login realizado com sucesso!',
            token,
            user: {
                id: user.id,
                nomeGuerra: user.nomeGuerra,
                nivelAcesso: user.nivelAcesso,
                entradacaps: user.entradacaps
            }
        });

    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({
            success: false,
            message: 'Erro interno do servidor durante o login.',
            error: error.message
        });
    }
});

// Rotas Protegidas (mantidas como estão)
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
        const { nomeCompleto, vulgo, antecedentes, vicios, nomeMae, cpf, rg, endereco, naturalidade, informacao, bolsafamilia, registropop, registropsocial, entradacaps } = req.body;
        const imagen = req.file ? req.file.filename : null;

        if (!nomeCompleto || !cpf) {
            return res.status(400).json({ success: false, message: 'Nome completo e CPF são campos obrigatórios.' });
        }

        const query = `
            INSERT INTO morador_rua (
                nomeCompleto, vulgo, antecedentes, vicios, nome_mae, cpf, rg, endereco, naturalidade, informacao,
                bolsafamilia, registropop, registropsocial, entradacaps, imagen
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        
        const [results] = await pool.execute(query, [
            nomeCompleto, vulgo || null, antecedentes || null, vicios || null, nomeMae || null,
            cpf, rg || null, endereco || null, naturalidade || null, informacao || '',
            bolsafamilia || '', registropop || '', registropsocial || '', entradacaps || null, imagen
        ]);

        res.status(201).json({
            success: true,
            message: 'Morador cadastrado com sucesso!',
            id: results.insertId
        });
    } catch (error) {
        console.error('Erro ao cadastrar morador:', error);
        res.status(500).json({
            success: false,
            message: 'Erro interno do servidor ao cadastrar o morador.',
            error: error.message
        });
    }
});

// Rotas CAPS (mantidas como estão)
app.get('/api/caps', authenticateToken, authorizeRoles(['caps', 'sim', 'nao']), (req, res) => {
    res.status(200).json({ message: `Bem-vindo, ${req.user.username}! Você tem acesso ao nível Operacional. Seu nível: ${req.user.entradacaps}.`, seucaps: req.user.entradacaps });
});

app.get('/api/sim', authenticateToken, authorizeRoles(['sim', 'nao']), (req, res) => {
    res.status(200).json({ message: `Bem-vindo, ${req.user.username}! Você tem acesso ao nível Tático. Seu nível: ${req.user.entradacaps}.`, seucaps: req.user.entradacaps });
});

app.get('/api/nao', authenticateToken, authorizeRoles(['nao']), (req, res) => {
    res.status(200).json({ message: `Bem-vindo, ${req.user.username}! Você tem acesso ao nível Estratégico. Seu nível: ${req.user.entradacaps}.`, seucaps: req.user.entradacaps });
});

// Rota de busca por morador
app.get('/api/moradores/busca', authenticateToken, async (req, res) => {
    const { nomeCompleto, cpf, rg } = req.query;

    if (!nomeCompleto && !cpf && !rg) {
        return res.status(400).json({ success: false, message: 'Pelo menos um critério de busca (nome, cpf ou rg) é obrigatório.' });
    }

    try {
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

        const [rows] = await pool.execute(query, params);
        res.status(200).json({ success: true, moradores: rows });
    } catch (error) {
        console.error('ERRO NA BUSCA:', error);
        res.status(500).json({ success: false, message: 'Erro interno do servidor durante a busca.' });
    }
});

// Rota para buscar morador por ID
app.get('/api/moradores/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;

    if (!id) {
        return res.status(400).json({ success: false, message: 'ID do morador é obrigatório.' });
    }

    try {
        const query = `SELECT * FROM morador_rua WHERE id = ?`;
        const [rows] = await pool.execute(query, [id]);

        if (rows.length > 0) {
            res.status(200).json({ success: true, morador: rows[0] });
        } else {
            res.status(404).json({ success: false, message: 'Morador não encontrado.' });
        }
    } catch (error) {
        console.error('ERRO NA BUSCA POR ID:', error);
        res.status(500).json({ success: false, message: 'Erro interno do servidor.' });
    }
});

// Inicia o Servidor
app.listen(port, () => {
    console.log(`Servidor Node.js rodando na porta ${port}`);
    console.log('Conectado ao banco de dados MySQL no Railway');
});