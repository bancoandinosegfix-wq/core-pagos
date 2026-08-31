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
    // Las directivas que no heredan de default-src (form-action, frame-ancestors, base-uri) y las
    // -elem/-attr van explícitas: omitirlas equivale a permitir todo, y el DAST las marca.
    res.setHeader('Content-Security-Policy', [
        "default-src 'none'", "script-src 'none'", "script-src-elem 'none'", "script-src-attr 'none'",
        "style-src 'none'", "style-src-elem 'none'", "style-src-attr 'none'", "img-src 'none'",
        "connect-src 'none'", "font-src 'none'", "object-src 'none'", "media-src 'none'",
        "frame-src 'none'", "child-src 'none'", "worker-src 'none'", "manifest-src 'none'",
        "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'",
    ].join('; '));
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

// El manejador de errores por defecto de Express (finalhandler) responde los 404 pisando la
// cabecera CSP con un `default-src 'none'` suelto, sin form-action ni frame-ancestors. Al ser
// una API JSON, el 404 se responde acá y así conserva la política completa.
app.use((req, res) => res.status(404).json({ error: 'RECURSO_NO_ENCONTRADO' }));

app.use((err, req, res, _next) => {
    auditoria.registrar('error_no_controlado', { ruta: req.path });
    res.status(500).json({ error: 'ERROR_INTERNO' });
});

if (require.main === module) {
    app.listen(config.puerto, () => console.log(`core-pagos escuchando en :${config.puerto}`));
}

module.exports = app;
