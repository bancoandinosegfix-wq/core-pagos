'use strict';
const express = require('express');
const config = require('./lib/config');
const { autenticar, emitirToken } = require('./lib/auth');
const transferencias = require('./routes/transferencias');
const auditoria = require('./services/auditoria');

const app = express();

// El core es una API JSON: no sirve HTML ni carga recursos, así que la política más
// restrictiva posible es también la correcta. Se declara default-src para que las
// directivas que no se listan tengan de dónde heredar.
app.disable('x-powered-by');
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy',
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    next();
});

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
