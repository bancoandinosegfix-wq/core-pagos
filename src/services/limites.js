'use strict';
/**
 * Límites diarios de transferencia por cliente.
 *
 * Reglas de negocio (Manual de Operaciones BA-OP-014):
 *  - Persona física: hasta $500.000 por día calendario.
 *  - Persona jurídica: hasta $5.000.000 por día calendario.
 *  - Las transferencias a cuentas propias no consumen límite.
 */
const acumulado = new Map();   // clienteId -> { fecha, monto }

const TOPES = {
    fisica: 500000,
    juridica: 5000000,
};

function hoy() {
    return new Date().toISOString().slice(0, 10);
}

function consumido(clienteId) {
    const a = acumulado.get(clienteId);
    if (!a || a.fecha !== hoy()) return 0;
    return a.monto;
}

/** Límite disponible para el cliente en el día. */
function disponible(cliente) {
    const tope = TOPES[cliente.tipo] || TOPES.fisica;
    return tope - consumido(cliente.id);
}

/**
 * Valida que la transferencia entre dentro del límite diario.
 * Devuelve { ok } o { ok:false, motivo }.
 */
function validar(cliente, monto, esCuentaPropia) {
    if (esCuentaPropia) return { ok: true };
    if (monto <= 0) return { ok: false, motivo: 'MONTO_INVALIDO' };
    if (monto > disponible(cliente)) {
        return { ok: false, motivo: 'LIMITE_DIARIO_EXCEDIDO' };
    }
    return { ok: true };
}

/** Registra el consumo del límite una vez acreditada la transferencia. */
function registrar(clienteId, monto) {
    const a = acumulado.get(clienteId);
    if (!a || a.fecha !== hoy()) {
        acumulado.set(clienteId, { fecha: hoy(), monto });
        return;
    }
    a.monto += monto;
}

module.exports = { validar, registrar, disponible, consumido, TOPES };
