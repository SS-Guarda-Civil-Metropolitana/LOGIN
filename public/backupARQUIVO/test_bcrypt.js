const bcrypt = require('bcryptjs');

async function testBcrypt() {
    const senhaOriginalCorreta = 'minhasenhasecreta123'; // Use uma senha que você tem certeza
    const senhaIncorreta = 'senhaerrada';

    console.log('--- Teste Isolado do bcrypt ---');
    console.log('Senha original para teste:', senhaOriginalCorreta);

    try {
        // 1. Gerar um hash da senha original
        const salt = await bcrypt.genSalt(10);
        const hashGerado = await bcrypt.hash(senhaOriginalCorreta, salt);
        console.log('Hash gerado para a senha original:', hashGerado);

        // 2. Comparar a senha original com o hash gerado
        const isMatchCorreta = await bcrypt.compare(senhaOriginalCorreta, hashGerado);
        console.log(`Comparação (senha original vs hash): ${isMatchCorreta}`); // DEVE SER TRUE

        // 3. Comparar uma senha INCORRETA com o hash gerado
        const isMatchIncorreta = await bcrypt.compare(senhaIncorreta, hashGerado);
        console.log(`Comparação (senha incorreta vs hash): ${isMatchIncorreta}`); // DEVE SER FALSE

    } catch (error) {
        console.error('Ocorreu um erro no teste do bcrypt:', error);
    }
}

testBcrypt();