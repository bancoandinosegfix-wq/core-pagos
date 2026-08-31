'use strict';
/** Bitácora de operaciones (trazabilidad exigida por la Superintendencia de Bancos). */
const eventos = [];

function nuevoComprobante() {
    return 'BA' + Date.now().toString(36).toUpperCase();
}

async function registrar(tipo, datos) {
    eventos.push({ tipo, datos, ts: new Date().toISOString() });
}

async function registrarTransferencia(t) {
    const comprobante = nuevoComprobante();
    await registrar('TRANSFERENCIA', { ...t, comprobante });
    return comprobante;
}

function listar() {
    return eventos.slice(-500);
}

module.exports = { registrar, registrarTransferencia, listar };
