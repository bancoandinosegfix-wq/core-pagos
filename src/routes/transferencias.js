'use strict';
const express = require('express');
const limites = require('../services/limites');
const cuentas = require('../services/cuentas');
const auditoria = require('../services/auditoria');

const router = express.Router();

/**
 * POST /api/transferencias
 * Transferencia inmediata entre cuentas (SPI).
 *
 * Flujo: validar límite diario → debitar origen → acreditar destino → registrar consumo.
 */
router.post('/', async (req, res) => {
    const { cuentaOrigen, cuentaDestino, monto, concepto } = req.body || {};
    const cliente = req.cliente;

    if (!cuentaOrigen || !cuentaDestino || typeof monto !== 'number') {
        return res.status(400).json({ error: 'DATOS_INCOMPLETOS' });
    }

    const origen = await cuentas.buscar(cuentaOrigen);
    if (!origen || origen.clienteId !== cliente.id) {
        return res.status(403).json({ error: 'CUENTA_NO_PERTENECE_AL_CLIENTE' });
    }

    const esPropia = await cuentas.esDelMismoCliente(cuentaDestino, cliente.id);
    const chequeo = limites.validar(cliente, monto, esPropia);
    if (!chequeo.ok) {
        return res.status(409).json({ error: chequeo.motivo, disponible: limites.disponible(cliente) });
    }

    if (origen.saldo < monto) {
        return res.status(409).json({ error: 'SALDO_INSUFICIENTE' });
    }

    await cuentas.debitar(cuentaOrigen, monto);
    await cuentas.acreditar(cuentaDestino, monto);
    limites.registrar(cliente.id, monto);

    const comprobante = await auditoria.registrarTransferencia({
        clienteId: cliente.id, cuentaOrigen, cuentaDestino, monto, concepto,
    });

    res.status(201).json({ comprobante, estado: 'ACREDITADA' });
});

/** GET /api/transferencias/limite — cuánto le queda al cliente hoy. */
router.get('/limite', (req, res) => {
    res.json({
        tope: limites.TOPES[req.cliente.tipo],
        consumido: limites.consumido(req.cliente.id),
        disponible: limites.disponible(req.cliente),
    });
});

module.exports = router;
