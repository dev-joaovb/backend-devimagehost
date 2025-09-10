const express = require('express');
const router = express.Router();

// Rota de teste/api
router.get('/teste', (req, res) => {
    res.json({ mensagem: 'Rota de teste/api está funcionando!' });
})

// Rota POST
router.post('/mensagem', (req, res) => {
    const { texto } = req.body;
    if (!texto) {
        return res.status(400).json({ erro: 'O campo texto é obrigatório.' });
    }
    res.json({ mensagem: `Você enviou: ${texto}` });
})

module.exports = router;