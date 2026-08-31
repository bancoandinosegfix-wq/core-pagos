'use strict';
/** Acceso a cuentas. En la demo son en memoria; en el core real va contra el host. */

const CUENTAS = new Map([
    ['0290001110000000012345', { clienteId: 'CLI-001', titular: 'Juan Pérez', saldo: 12500, tipo: 'CA' }],
    ['0290001110000000067890', { clienteId: 'CLI-001', titular: 'Juan Pérez', saldo: 3800, tipo: 'CC' }],
    ['0290001110000000099999', { clienteId: 'CLI-002', titular: 'Comercial Andina Cía. Ltda.', saldo: 84000, tipo: 'CC' }],
    ['0110004420000000054321', { clienteId: 'EXT', titular: 'Cuenta externa', saldo: 0, tipo: 'CA' }],
]);

async function buscar(cuenta) {
    const c = CUENTAS.get(cuenta);
    return c ? { cuenta, ...c } : null;
}

async function esDelMismoCliente(cuenta, clienteId) {
    const c = CUENTAS.get(cuenta);
    return !!c && c.clienteId === clienteId;
}

async function debitar(cuenta, monto) {
    const c = CUENTAS.get(cuenta);
    if (!c) throw new Error('CUENTA_INEXISTENTE');
    c.saldo -= monto;
    return c.saldo;
}

async function acreditar(cuenta, monto) {
    const c = CUENTAS.get(cuenta);
    if (!c) return null;          // cuenta de otra entidad: se acredita por el SPI
    c.saldo += monto;
    return c.saldo;
}

module.exports = { buscar, esDelMismoCliente, debitar, acreditar };
