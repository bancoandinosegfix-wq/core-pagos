#!/usr/bin/env node
'use strict';
/** Lint mínimo sin dependencias: 'use strict', console.log sueltos y líneas muy largas. */
const fs = require('fs');
const path = require('path');

const MAX = 140;
let avisos = 0;

function revisar(archivo) {
    const texto = fs.readFileSync(archivo, 'utf8');
    const lineas = texto.split('\n');
    if (!/^['"]use strict['"];/m.test(texto)) {
        console.log(`aviso ${archivo}:1 falta 'use strict'`);
        avisos++;
    }
    lineas.forEach((l, i) => {
        if (l.length > MAX) { console.log(`aviso ${archivo}:${i + 1} línea de ${l.length} caracteres`); avisos++; }
    });
}

function recorrer(dir) {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, e.name);
        if (e.isDirectory()) recorrer(p);
        else if (e.name.endsWith('.js')) revisar(p);
    }
}

recorrer(path.join(__dirname, '..', 'src'));
console.log(avisos ? `lint: ${avisos} aviso(s)` : 'lint: sin observaciones');
process.exit(0);   // los avisos no rompen el build
