const bcrypt = require('bcryptjs');

const senhaDigitada = 'hugo'; // A senha que você ACHA que é
const hashDoBanco = '$2b$10$oM9a.zZQdaQHRNI6xPP0N.yY.rWVgqESR9/p8n/kQTQ'; // O hash COPIADO DO BANCO DE DADOS

async function testCompare() {
    const isMatch = await bcrypt.compare(senhaDigitada, hashDoBanco);
    console.log(`Senha digitada: '${senhaDigitada}' (Comprimento: ${senhaDigitada.length})`);
    console.log(`Hash do banco: '${hashDoBanco}' (Comprimento: ${hashDoBanco.length})`);
    console.log('Resultado da comparação:', isMatch);
}

testCompare();