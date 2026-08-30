'use strict';
/**
 * Conciliación interbancaria.
 *
 * Todas las noches (02:00) el core intercambia los archivos de interfaz con las demás entidades
 * a través de SFTP: se sube el lote de movimientos del día y se baja el de la cámara compensadora.
 * Es el canal por el que entra y sale TODO el volumen interbancario del banco.
 *
 * Contraparte: cámara compensadora (COELSA) y bancos corresponsales.
 * Ventana: 02:00–04:00. Si falla, la acreditación del día siguiente se demora.
 */
const SftpClient = require('ssh2-sftp-client');
const config = require('../lib/config');
const auditoria = require('./auditoria');

const RUTA_SALIDA = '/interfaces/salida';
const RUTA_ENTRADA = '/interfaces/entrada';

async function conectar() {
    const sftp = new SftpClient();
    await sftp.connect({
        host: config.sftp.host,
        port: config.sftp.port,
        username: config.sftp.usuario,
        password: config.sftp.password,
        readyTimeout: 20000,
    });
    return sftp;
}

/** Sube el lote de movimientos del día a la cámara compensadora. */
async function enviarLote(fecha, contenido) {
    const sftp = await conectar();
    try {
        const destino = `${RUTA_SALIDA}/MOV_${fecha.replace(/-/g, '')}.txt`;
        await sftp.put(Buffer.from(contenido, 'utf8'), destino);
        await auditoria.registrar('CONCILIACION_ENVIO', { fecha, destino });
        return destino;
    } finally {
        await sftp.end();
    }
}

/** Baja el archivo de la cámara y devuelve los movimientos a aplicar. */
async function recibirLote(fecha) {
    const sftp = await conectar();
    try {
        const origen = `${RUTA_ENTRADA}/CAM_${fecha.replace(/-/g, '')}.txt`;
        const buf = await sftp.get(origen);
        await auditoria.registrar('CONCILIACION_RECEPCION', { fecha, origen });
        return parsearLote(buf.toString('utf8'));
    } finally {
        await sftp.end();
    }
}

/** Formato posicional acordado con la cámara: CBU(22) TIPO(2) MONTO(15) REFERENCIA(20). */
function parsearLote(texto) {
    return texto.split('\n').filter(Boolean).map((linea) => ({
        cbu: linea.slice(0, 22).trim(),
        tipo: linea.slice(22, 24).trim(),
        monto: Number(linea.slice(24, 39).trim()) / 100,
        referencia: linea.slice(39, 59).trim(),
    }));
}

module.exports = { enviarLote, recibirLote, parsearLote };
