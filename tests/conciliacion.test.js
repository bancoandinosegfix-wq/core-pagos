'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { parsearLote } = require('../src/services/conciliacion');

// Formato posicional acordado con la cámara: CBU(22) TIPO(2) MONTO(15) REFERENCIA(20)
const LINEA = '0290001110000000012345' + 'CR' + '000000012500000' + 'REF-COELSA-000012  ';

test('parsea una línea del lote de la cámara', () => {
    const [m] = parsearLote(LINEA);
    assert.strictEqual(m.cbu, '0290001110000000012345');
    assert.strictEqual(m.tipo, 'CR');
    assert.strictEqual(m.monto, 125000);
    assert.strictEqual(m.referencia, 'REF-COELSA-000012');
});

test('ignora líneas vacías del archivo', () => {
    assert.strictEqual(parsearLote(`${LINEA}\n\n${LINEA}\n`).length, 2);
});

test('un lote vacío no rompe la conciliación', () => {
    assert.deepStrictEqual(parsearLote(''), []);
});
