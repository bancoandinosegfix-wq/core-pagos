'use strict';
/** Configuración del core. En producción llega por variables de entorno. */
module.exports = {
    puerto: process.env.PORT || 8080,

    // Firma de los tokens de sesión del homebanking.
    jwtSecret: process.env.JWT_SECRET || 'BA_core_pagos_2019_clave_provisoria',

    // Canal de interfaces con la cámara compensadora (ver services/conciliacion.js).
    sftp: {
        host: process.env.SFTP_HOST || 'sftp.camara-compensadora.test',
        port: Number(process.env.SFTP_PORT || 22),
        usuario: process.env.SFTP_USER || 'bandino_interfaces',
        password: process.env.SFTP_PASSWORD || 'Interf4ces#2021',
    },

    // Servicio de scoring crediticio (consulta externa).
    scoring: {
        baseUrl: process.env.SCORING_URL || 'https://scoring.interno.bandino.test',
        apiKey: process.env.SCORING_API_KEY || '',
    },
};
