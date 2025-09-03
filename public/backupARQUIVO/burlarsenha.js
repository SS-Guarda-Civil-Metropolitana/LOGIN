// server.js

const express = require('express');
const mysql = require('mysql2/promise'); // Usando a versão 'promise' para async/await
const bcrypt = require('bcryptjs'); // Para hashing de senhas
const cors = require('cors'); // Para permitir requisições de origens diferentes
require('dotenv').config(); // Carrega variáveis de ambiente do arquivo .env
const path = require('path');
const jwt = require('jsonwebtoken'); // <--- IMPORTAÇÃO NECESSÁRIA PARA JWT

const app = express();
const port = process.env.PORT || 3001;

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
        req.user = user; // Adiciona os dados do usuário decodificados ao objeto req
        next(); // Continua para a próxima função middleware/rota
    });
};

const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'policia_municipal' // Substitua pelo nome do seu banco de dados
};

// Rota para cadastrar usuários do sistema
app.post('/cadastrar', async (req, res) => {
    const { nomeCompleto, nomeGuerra, cpf, email, matricula, senha } = req.body;

    // Validação básica para este tipo de usuário
    if (!nomeCompleto || !cpf || !email || !matricula || !senha) {
        return res.status(400).json({ success: false, message: 'Todos os campos obrigatórios (Nome Completo, CPF, E-mail, Matrícula, Senha) devem ser preenchidos.' });
    }

    console.log('--- CADASTRO: INÍCIO ---');
    console.log('CADASTRO: Senha recebida do frontend (texto claro ANTES do hash):', `'${senha}'`);
    console.log('CADASTRO: Comprimento da senha:', senha.length);

    try {
        const connection = await mysql.createConnection(dbConfig);
        console.log('CADASTRO: Conexão com o BD estabelecida.');

        const salt = await bcrypt.genSalt(10); // bcrypt.genSalt(10) é mais comum
        const senhaHash = await bcrypt.hash(senha, salt);
        console.log('CADASTRO: Senha Hasheada (para salvar no DB):', senhaHash);
        console.log('CADASTRO: Tipo da senha hasheada:', typeof senhaHash);

        const query = `
            INSERT INTO usuarios (nome_completo, nome_guerra, cpf, email, matricula, senha)
            VALUES (?, ?, ?, ?, ?, ?)
        `;
        // CORRIGIDO: nomeGuerra || '' para campos NOT NULL opcionais e ordem correta
        const [rows] = await connection.execute(query, [nomeCompleto, nomeGuerra || '', cpf, email, matricula, senhaHash]);
        await connection.end(); // AWAIT ADICIONADO

        if (rows.affectedRows === 1) {
            console.log('CADASTRO: Usuário cadastrado com sucesso no BD. Enviando 201 Created.');
            return res.status(201).json({ success: true, message: 'Usuário do Sistema cadastrado com sucesso!' });
        } else {
            console.log('CADASTRO: Erro: Nenhuma linha afetada. Enviando 500.');
            return res.status(500).json({ success: false, message: 'Erro ao cadastrar usuário do sistema. Nenhuma linha afetada.' });
        }

    } catch (error) {
        console.error('ERRO NO CADASTRO (CATCH):', error);
        if (connection) await connection.end(); // AWAIT ADICIONADO
        if (error.code === 'ER_DUP_ENTRY') {
            let field = 'campo';
            if (error.message.includes('cpf')) field = 'CPF';
            else if (error.message.includes('email')) field = 'E-mail';
            else if (error.message.includes('matricula')) field = 'Matrícula';
            return res.status(409).json({ success: false, message: `Erro: ${field} já cadastrado no sistema.` });
        }
        return res.status(500).json({ success: false, message: 'Erro interno do servidor ao cadastrar usuário do sistema.' });
    }
});

// Rota de LOGIN
// server.js
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    console.log('--- LOGIN: INÍCIO (Teste de Ignorar Senha) ---');
    console.log('Username recebido:', username);
    console.log('Senha recebida do frontend (IGNORADA):', `'${password}'`); // A senha será ignorada

    if (!username) { // Valida apenas o username
        return res.status(400).json({ success: false, message: 'Usuário é obrigatório.' });
    }

    let connection;
    try {
        connection = await mysql.createConnection(dbConfig);

        const [rows] = await connection.execute(
            'SELECT * FROM usuarios WHERE email = ? OR cpf = ? OR matricula = ? OR nome_guerra = ?',
            [username, username, username, username]
        );

        console.log('Conteúdo de rows após a busca no DB:', rows);

        if (rows.length === 0) {
            await connection.end();
            console.log('ERRO: Usuário não encontrado no DB com o identificador fornecido.');
            return res.status(401).json({ success: false, message: 'Credenciais inválidas. Usuário não encontrado.' });
        }

        const user = rows[0];
        console.log('Usuário encontrado no DB:', user.nome_completo, user.nome_guerra, user.email);
        // console.log('Hash de senha do DB (user.senha):', user.senha); // Pode remover este log

        // --- AQUI ESTÁ A MUDANÇA CRÍTICA: IGNORA A COMPARAÇÃO DE SENHA ---
        const isMatch = true; // <--- SEMPRE TRUE PARA TESTE!
        console.log('RESULTADO DO TESTE (Senha Ignorada): isMatch é sempre TRUE');
        // --- FIM DA MUDANÇA CRÍTICA ---

        if (!isMatch) { // Este bloco não será atingido com isMatch = true
            await connection.end();
            console.log('ERRO: Senha incorreta para o usuário encontrado. (Este log não deveria aparecer no teste)');
            return res.status(401).json({ success: false, message: 'Credenciais inválidas. Senha incorreta.' });
        }

        // Se as credenciais são válidas (usuário encontrado e isMatch = true)
        const token = jwt.sign(
            { id: user.id, username: user.email, role: user.role || 'user' },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        await connection.end();

        res.status(200).json({
            success: true,
            message: 'Login realizado com sucesso! (Senha ignorada para teste)',
            token: token,
            user: { id: user.id, nomeCompleto: user.nome_completo, email: user.email, matricula: user.matricula }
        });

    } catch (error) {
        console.error('ERRO NO PROCESSO DE LOGIN (CATCH):', error);
        if (connection) await connection.end();
        res.status(500).json({ success: false, message: 'Erro interno do servidor durante o login.' });
    }
});

app.post('/api/moradores', async (req, res) => {
    try {
        const connection = await mysql.createConnection(dbConfig);

        const {
            nomeCompleto,
            vulgo,
            antecedentes,
            vicios,
            nomeMae,
            cpf,
            rg,
            endereco,
            naturalidade,
            informacao, // Este é o campo 'informacoesAdicionais' do frontend
            bolsafamilia, // Este é o campo 'registroBolsaFamilia' do frontend
            registropop, // Verifique se este campo está no seu formulário
            registropsocial,
            entradacaps
        } = req.body;

        // Validação Básica
        if (!nomeCompleto || !cpf) {
            await connection.end(); // AWAIT ADICIONADO AQUI
            return res.status(400).json({ success: false, message: 'Nome completo e CPF são campos obrigatórios.' });
        }

        const query = `
            INSERT INTO morador_rua (
                nomeCompleto, vulgo, antecedentes, vicios, nome_mae, cpf, rg, endereco, naturalidade, informacao,
            bolsafamilia, registropop, registropsocial, entradacaps
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        const [results] = await connection.execute(query, [
            nomeCompleto,
            vulgo || null,
            antecedentes || null,
            vicios || null,
            nomeMae || null,
            cpf,
            rg || null,
            endereco || null,
            naturalidade || null,
            informacao || '',
            bolsafamilia || '',
            registropop || '',
            registropsocial || '',
            entradacaps || '',
        ]);

        await connection.end(); // AWAIT ADICIONADO AQUI

        res.status(201).json({
            success: true,
            message: 'Morador cadastrado com sucesso!',
            id: results.insertId
        });

    } catch (error) {
        console.error('Erro ao cadastrar morador:', error);
        if (connection) await connection.end(); // AWAIT ADICIONADO AQUI
        res.status(500).json({
            success: false,
            message: 'Erro interno do servidor ao cadastrar o morador.',
            error: error.message
        });
    }
});

// Rota para servir a página de login
app.get('/login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Rota principal (pode ser o login ou sua dashboard inicial)
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Inicia o Servidor
app.listen(port, () => {
    console.log(`Servidor Node.js rodando em http://localhost:${port}`);
    console.log(`Frontend acessível em http://localhost:${port}/`);
    console.log(`Endpoint de cadastro (POST): http://localhost:${port}/api/moradores`);
    console.log(`Endpoint de Login (POST): http://localhost:${port}/api/login`);
});