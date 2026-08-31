'use strict';
const jwt = require('jsonwebtoken');
const config = require('./config');

const CLIENTES = {
    'CLI-001': { id: 'CLI-001', nombre: 'Juan Pérez', tipo: 'fisica' },
    'CLI-002': { id: 'CLI-002', nombre: 'Comercial Andina Cía. Ltda.', tipo: 'juridica' },
};

/** Middleware: valida el token del homebanking y deja el cliente en req.cliente. */
function autenticar(req, res, next) {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
    if (!token) return res.status(401).json({ error: 'SIN_TOKEN' });
    try {
        const payload = jwt.verify(token, config.jwtSecret);
        const cliente = CLIENTES[payload.sub];
        if (!cliente) return res.status(401).json({ error: 'CLIENTE_INEXISTENTE' });
        req.cliente = cliente;
        next();
    } catch (e) {
        return res.status(401).json({ error: 'TOKEN_INVALIDO' });
    }
}

function emitirToken(clienteId) {
    return jwt.sign({ sub: clienteId }, config.jwtSecret, { expiresIn: '30m' });
}

module.exports = { autenticar, emitirToken, CLIENTES };
