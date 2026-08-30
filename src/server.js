'use strict';
const express = require('express');
const config = require('./lib/config');
const { autenticar, emitirToken } = require('./lib/auth');
const transferencias = require('./routes/transferencias');
const auditoria = require('./services/auditoria');

const app = express();
app.use(express.json());

app.get('/health', (req, res) => res.json({ ok: true, servicio: 'core-pagos', version: '2.4.0' }));

// Login del homebanking (en el core real delega en el IdP del banco).
app.post('/api/login', (req, res) => {
    const { clienteId } = req.body || {};
    if (!clienteId) return res.status(400).json({ error: 'CLIENTE_REQUERIDO' });
    res.json({ token: emitirToken(clienteId) });
});

app.use('/api/transferencias', autenticar, transferencias);

app.get('/api/auditoria', autenticar, (req, res) => res.json({ eventos: auditoria.listar() }));

if (require.main === module) {
    app.listen(config.puerto, () => console.log(`core-pagos escuchando en :${config.puerto}`));
}

module.exports = app;
