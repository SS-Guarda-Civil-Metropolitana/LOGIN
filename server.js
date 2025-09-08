const express = require('express');
const mysql = require('mysql2/promise'); // Usando a versão 'promise' para async/await
const bcrypt = require('bcryptjs'); // Para hashing de senhas
const cors = require('cors'); // Para permitir requisições de origens diferentes
require('dotenv').config(); // Carrega variáveis de ambiente do arquivo .env
const multer = require('multer');
const path = require('path');
const jwt = require('jsonwebtoken'); // <--- IMPORTAÇÃO NECESSÁRIA PARA JWT
const app = express();
const port = process.env.PORT || 3001;

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        // Crie uma pasta 'uploads' dentro da pasta 'public'
        cb(null, 'public/uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage: storage });

// --- Configuração CORS ---
const corsOptions = {
    origin: '*', // APENAS PARA DESENVOLVIMENTO/TESTES. NUNCA EM PRODUÇÃO!
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE', // Permite todos os métodos para teste
    allowedHeaders: ['Content-Type', 'Authorization'] // Permite cabeçalhos comuns
};
app.use(cors(corsOptions));

app.use(express.static('public')); // Serve arquivos estáticos da pasta 'public'
app.use(express.json()); // Permite que o Express leia JSON do corpo das requisições POST

// <--- CHAVE SECRETA PARA ASSINAR E VERIFICAR TOKENS JWT. MUDE ISSO EM PRODUÇÃO!
const JWT_SECRET = process.env.JWT_SECRET || 'sua_chave_secreta_muito_segura_e_longa_aqui';

// Middleware de Autenticação (coloque-o após o app.use(express.json());)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Formato: Bearer TOKEN

    if (!token) {
        return res.status(401).json({ message: 'Acesso negado. Token não fornecido.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Token inválido ou expirado.' });
        }
        req.user = user; // Adiciona os dados do usuário decodificados ao objeto req (inclui id, username, role, nivelAcesso)
        next();
    });
};

// NOVO Middleware de Autorização por Nível de Acesso
const authorizeRoles = (allowedRoles) => {
    return (req, res, next) => {
        // req.user é definido pelo middleware authenticateToken
        if (!req.user || !req.user.nivelAcesso || req.user.entradacaps) {
            return res.status(403).json({ message: 'Acesso negado. Nível de acesso não definido no token.' });
        }

        const userRole = req.user.nivelAcesso || req.user.entradacaps;
        console.log(`Verificando permissão: Usuário '${req.user.username}' (ID: ${req.user.id}) tem nível '${userRole}'. Requer: ${allowedRoles.join(', ')}`);
        if (allowedRoles.includes(userRole)) {
            next(); // Usuário tem a permissão, continua
        } else {
            return res.status(403).json({ message: `Acesso negado. Você não tem permissão para esta operação. Seu nível: ${userRole}.` });
        }
    };
};


/* AQUI É CONEXAO COM BANCO DE DADOS NO SERVIDOR LOCAL XAMPP MYSQL//
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'policia_municipal'
};
*/

const dbConfig = {
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE
};

const connection = mysql.createConnection(dbConfig);


// Rota para cadastrar usuários do sistema
app.post('/cadastrar', async (req, res) => {
    const { nomeCompleto, nomeGuerra, cpf, email, matricula, senha, nivelAcesso } = req.body;

    // Validação básica para este tipo de usuário
    if (!nomeCompleto || !cpf || !email || !matricula || !senha) {
        return res.status(400).json({ success: false, message: 'Todos os campos obrigatórios (Nome Completo, CPF, E-mail, Matrícula, Senha) devem ser preenchidos.' });
    }

    console.log('--- CADASTRO: INÍCIO ---');
    console.log('CADASTRO: Senha recebida do frontend (texto claro ANTES do hash):', `'${senha}'`);
    console.log('CADASTRO: Comprimento da senha:', senha.length);
    console.log('CADASTRO: Nível de Acesso recebido (se houver):', nivelAcesso);

    let connection; // Declare connection aqui para que esteja disponível no catch externo e na nova verificação
    try {
        connection = await mysql.createConnection(dbConfig);
        console.log('CADASTRO: Conexão com o BD estabelecida.');
        // --- NOVO: VERIFICAÇÃO SE O USUÁRIO JÁ EXISTE POR CPF, EMAIL, MATRÍCULA OU NOME DE GUERRA ---
        const checkQuery = `
            SELECT id, cpf, email, matricula, nome_guerra FROM usuarios
            WHERE cpf = ? OR email = ? OR matricula = ? OR nome_guerra = ?
            LIMIT 1
        `;
        const [existingUsers] = await connection.execute(checkQuery, [cpf, email, matricula, nomeGuerra]);
        if (existingUsers.length > 0) {
            const existingUser = existingUsers[0];
            let field = '';
            if (existingUser.cpf === cpf) field = 'CPF';
            else if (existingUser.email === email) field = 'E-mail';
            else if (existingUser.matricula === matricula) field = 'Matrícula';
            else if (existingUser.nome_guerra === nomeGuerra) field = 'Nome de Guerra';

            await connection.end(); // Fechar conexão antes de retornar
            console.log(`CADASTRO: Tentativa de cadastro com ${field} já existente.`);
            return res.status(409).json({ success: false, message: `Este ${field} já está cadastrado no sistema.` });
        }
        // --- FIM DA NOVA VERIFICAÇÃO ---

        const salt = await bcrypt.genSalt(10);
        const senhaHash = await bcrypt.hash(senha, salt);
        console.log('CADASTRO: Senha Hasheada (para salvar no DB):', senhaHash);
        console.log('CADASTRO: Tipo da senha hasheada:', typeof senhaHash);

        const insertQuery = `
            INSERT INTO usuarios (nome_completo, nome_guerra, cpf, email, matricula, senha, nivel_acesso)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;
        const [rows] = await connection.execute(insertQuery, [
            nomeCompleto,
            nomeGuerra || '',
            cpf,
            email,
            matricula,
            senhaHash,
            nivelAcesso || 'Operacional'
        ]);
        await connection.end();

        if (rows.affectedRows === 1) {
            console.log('CADASTRO: Usuário cadastrado com sucesso no BD. Enviando 201 Created.');
            return res.status(201).json({ success: true, message: 'Usuário cadastrado com sucesso!' });
        } else {
            console.log('CADASTRO: Erro: Nenhuma linha afetada. Enviando 500.');
            return res.status(500).json({ success: false, message: 'Erro ao cadastrar usuário. Nenhuma linha afetada.' });
        }

    } catch (error) {
        console.error('ERRO NO CADASTRO (CATCH):', error);
        if (connection) await connection.end(); // Garante que a conexão é fechada
        // O bloco ER_DUP_ENTRY no catch é uma redundância agora,
        // mas é bom para garantir se houver UNIQUE constraints no DB
        if (error.code === 'ER_DUP_ENTRY') {
            let field = 'campo';
            // Mensagens mais genéricas para o usuário se for ER_DUP_ENTRY do DB
            if (error.message.includes('cpf')) field = 'CPF';
            else if (error.message.includes('email')) field = 'E-mail';
            else if (error.message.includes('matricula')) field = 'Matrícula';
            else if (error.message.includes('nome_guerra')) field = 'Nome de Guerra';
            return res.status(409).json({ success: false, message: `Este ${field} já está cadastrado no sistema.` });
        }
        return res.status(500).json({ success: false, message: 'Erro interno do servidor ao cadastrar usuário.' });
    }
});

// Rota de LOGIN
app.post('/api/login', async (req, res) => {
    const { username, password, tipoAcesso } = req.body;

    // --- Logs de Depuração ---
    console.log('--- LOGIN: INÍCIO ---');
    console.log('LOGIN: Username recebido:', username);
    console.log('LOGIN: Senha recebida do frontend (texto claro para comparar):', `'${password}'`);
    console.log('LOGIN: Comprimento da senha:', password.length);
    console.log('LOGIN: Tipo da senha recebida no login:', typeof password);
    console.log('LOGIN: Tipo de Acesso selecionado no frontend:', tipoAcesso);
    // --- Fim dos Logs ---

    // Validação básica
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Usuário e senha são obrigatórios.' });
    }

    let connection;
    try {
        connection = await mysql.createConnection(dbConfig);
        console.log('LOGIN: Conexão com o BD estabelecida.');

        const searchUsername = username || '';

        // Buscar o usuário pelo e-mail, CPF, matrícula ou nome_guerra
        // CORRIGIDO: nome_guerra na query para corresponder ao DB (snake_case)
        const [rows] = await connection.execute(
            'SELECT * FROM usuarios WHERE email = ? OR cpf = ? OR matricula = ? OR nome_guerra = ?',
            [searchUsername, searchUsername, searchUsername, searchUsername]
        );
        // --- Logs de Depuração ---
        console.log('LOGIN: Conteúdo de rows após a busca no DB:', rows);
        // --- Fim dos Logs ---

        if (rows.length === 0) {
            await connection.end();
            console.log('LOGIN: ERRO: Usuário não encontrado no DB com o identificador fornecido.');
            return res.status(401).json({ success: false, message: 'Usuário não encontrado.' });
        }

        const user = rows[0];
        // --- Logs de Depuração ---
        console.log(': Usuário encontrado no DB:', user.nome_completo, user.nome_guerra, user.email);
        console.log('LOGIN: Nível de Acesso do usuário no DB:', user.nivel_acesso);
        console.log('LOGIN: Hash de senha do DB (user.senha):', user.senha);
        console.log('LOGIN: TiLOGINpo do hash do DB (antes da conversão):', typeof user.senha);
        // --- Fim dos Logs ---

        // CONVERSÃO CRÍTICA: Garante que user.senha é uma string antes de comparar
        const storedHash = String(user.senha);
        console.log('LOGIN: Hash armazenado (após String() ):', storedHash);
        console.log('LOGIN: Tipo do hash armazenado (após String() ):', typeof storedHash);
        // Compara a senha fornecida com o hash armazenado
        const isMatch = await bcrypt.compare(password, storedHash);
        // PARA TESTES TEMPORÁRIOS: const isMatch = true; // CUIDADO: ISSO DESABILITA A SEGURANÇA!

        console.log('LOGIN: Resultado da comparação (isMatch):', isMatch);
        // LOG CRÍTICO

        if (!isMatch) {
            await connection.end();
            console.log('LOGIN: ERRO: Senha incorreta para o usuário encontrado.');
            return res.status(401).json({ success: false, message: 'Senha incorreta.' });
        }

        // --- NOVO: Lógica para verificar se o tipo de acesso selecionado corresponde ao do usuário no DB ---
        // Se o usuário selecionou um nível no frontend, ele deve bater com o nível no DB
        if (tipoAcesso && user.nivel_acesso && user.nivel_acesso !== tipoAcesso) {
            await connection.end();
            console.log(`LOGIN: ERRO: Nível de acesso selecionado (${tipoAcesso}) não corresponde ao nível do usuário no DB (${user.nivel_acesso}).`);
            return res.status(403).json({ success: false, message: `Nível de acesso incorreto. Seu nível é: ${user.nivel_acesso}.` });
        }
        // --- FIM DA LÓGICA DE VERIFICAÇÃO DO TIPO DE ACESSO ---


        // Se as credenciais e o nível de acesso (se verificado) são válidos, gerar um token JWT
        const token = jwt.sign(
            { id: user.id, username: user.email, role: user.role || 'user', nivelAcesso: user.nivel_acesso }, // Inclua nivelAcesso no payload!
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        await connection.end();
        res.status(200).json({
            success: true,
            message: 'Login realizado com sucesso!',
            token: token,
            user: { id: user.id, nomeCompleto: user.nome_completo, email: user.email, matricula: user.matricula, nivelAcesso: user.nivel_acesso }
        });
    } catch (error) {
        console.error('ERRO NO PROCESSO DE LOGIN (CATCH):', error);
        if (connection) await connection.end();
        res.status(500).json({ success: false, message: 'Erro interno do servidor durante o login.' });
    }
});
// --- EXEMPLOS DE ROTAS PROTEGIDAS POR NÍVEL DE ACESSO ---
// Rotas que exigem AUTENTICAÇÃO E NÍVEL DE ACESSO ESPECÍFICO
app.get('/api/acesso-operacional', authenticateToken, authorizeRoles(['Operacional', 'Tatico', 'Estrategico']), (req, res) => {
    res.status(200).json({ message: `Bem-vindo, ${req.user.username}! Você tem acesso ao nível Operacional. Seu nível: ${req.user.nivelAcesso}.`, seuNivel: req.user.nivelAcesso });
});
app.get('/api/acesso-tatico', authenticateToken, authorizeRoles(['Tatico', 'Estrategico']), (req, res) => {
    res.status(200).json({ message: `Bem-vindo, ${req.user.username}! Você tem acesso ao nível Tático. Seu nível: ${req.user.nivelAcesso}.`, seuNivel: req.user.nivelAcesso });
});
app.get('/api/acesso-estrategico', authenticateToken, authorizeRoles(['Estrategico']), (req, res) => {
    res.status(200).json({ message: `Bem-vindo, ${req.user.username}! Você tem acesso ao nível Estratégico. Seu nível: ${req.user.nivelAcesso}.`, seuNivel: req.user.nivelAcesso });
});
// Rota de cadastro de morador (EXEMPLO) - Protegida por níveis
// Assumindo que apenas 'Tatico' e 'Estrategico' podem cadastrar moradores
app.post('/api/moradores', upload.single('imagen'), async (req, res) => {
    try {
        const connection = await mysql.createConnection(dbConfig);
        // Agora os dados do formulário estão em req.body
        const { nomeCompleto, vulgo, antecedentes, vicios, nomeMae, cpf, rg, endereco, naturalidade, informacao, bolsafamilia, registropop, registropsocial, entradacaps } = req.body;
        // O caminho do arquivo salvo está em req.file
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
// Rotas para servir páginas HTML
app.get('/login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
app.get('/cadUsuario.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'cadUsuario.html'));
});
app.get('/principal.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'principal.html'));
});
// Rota principal (default)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
// --- Rota para buscar morador de rua na tabela e colocar no meu frint-end da tabela de buscar morador de rua---
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

// Inicia o Servidor
app.listen(port, () => {
    console.log(`Servidor Node.js rodando em http://localhost:${port}`);
    console.log(`Frontend acessível em http://localhost:${port}/`);
    console.log(`Endpoint de cadastro (POST): http://localhost:${port}/api/moradores`);
    console.log(`Endpoint de Login (POST): http://localhost:${port}/api/login`);
});