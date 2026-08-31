'use strict';
const test = require('node:test');
const assert = require('node:assert');
const limites = require('../src/services/limites');

const fisica = { id: 'T-FIS', tipo: 'fisica' };
const juridica = { id: 'T-JUR', tipo: 'juridica' };

test('una persona natural arranca con el tope diario disponible', () => {
    assert.strictEqual(limites.disponible({ id: 'T-NUEVO', tipo: 'fisica' }), 5000);
});

test('acepta una transferencia dentro del límite', () => {
    assert.deepStrictEqual(limites.validar(fisica, 1000, false), { ok: true });
});

test('rechaza una transferencia que supera el tope diario', () => {
    const r = limites.validar(fisica, 9000, false);
    assert.strictEqual(r.ok, false);
    assert.strictEqual(r.motivo, 'LIMITE_DIARIO_EXCEDIDO');
});

test('rechaza montos no positivos', () => {
    assert.strictEqual(limites.validar(fisica, 0, false).ok, false);
    assert.strictEqual(limites.validar(fisica, -50, false).ok, false);
});

test('las transferencias a cuenta propia no consumen límite', () => {
    assert.deepStrictEqual(limites.validar(fisica, 40000, true), { ok: true });
});

test('el consumo acumulado descuenta del disponible', () => {
    const c = { id: 'T-ACUM', tipo: 'fisica' };
    limites.registrar(c.id, 2000);
    assert.strictEqual(limites.disponible(c), 3000);
});

test('una persona jurídica tiene tope ampliado', () => {
    assert.deepStrictEqual(limites.validar(juridica, 30000, false), { ok: true });
});
