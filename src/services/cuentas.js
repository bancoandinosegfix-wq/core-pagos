'use strict';
/** Acceso a cuentas. En la demo son en memoria; en el core real va contra el host. */

const CUENTAS = new Map([
    ['0290001110000000012345', { clienteId: 'CLI-001', titular: 'Juan Pérez', saldo: 1250000, tipo: 'CA' }],
    ['0290001110000000067890', { clienteId: 'CLI-001', titular: 'Juan Pérez', saldo: 380000, tipo: 'CC' }],
    ['0290001110000000099999', { clienteId: 'CLI-002', titular: 'Logística Sur SRL', saldo: 8400000, tipo: 'CC' }],
    ['0110004420000000054321', { clienteId: 'EXT', titular: 'Cuenta externa', saldo: 0, tipo: 'CA' }],
]);

async function buscar(cbu) {
    const c = CUENTAS.get(cbu);
    return c ? { cbu, ...c } : null;
}

async function esDelMismoCliente(cbu, clienteId) {
    const c = CUENTAS.get(cbu);
    return !!c && c.clienteId === clienteId;
}

async function debitar(cbu, monto) {
    const c = CUENTAS.get(cbu);
    if (!c) throw new Error('CUENTA_INEXISTENTE');
    c.saldo -= monto;
    return c.saldo;
}

async function acreditar(cbu, monto) {
    const c = CUENTAS.get(cbu);
    if (!c) return null;          // cuenta de otra entidad: se acredita por la cámara
    c.saldo += monto;
    return c.saldo;
}

module.exports = { buscar, esDelMismoCliente, debitar, acreditar };
