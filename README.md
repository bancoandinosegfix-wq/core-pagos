# Core de Pagos — Banco Andino

API del core transaccional: transferencias inmediatas, límites diarios por cliente y conciliación
interbancaria con la cámara de compensación del BCE.

## Módulos

| Módulo | Qué hace |
|---|---|
| `src/routes/transferencias.js` | Transferencias entre cuentas (SPI) y consulta de límite disponible |
| `src/services/limites.js` | Límites diarios por tipo de cliente (BA-OP-014) |
| `src/services/conciliacion.js` | **Intercambio de interfaces por SFTP** con la cámara de compensación del BCE (ventana 02:00–04:00) |
| `src/services/cuentas.js` | Saldos, débito y crédito |
| `src/services/auditoria.js` | Bitácora de operaciones (Superintendencia de Bancos) |
| `src/lib/auth.js` | Sesión del homebanking (JWT) |

## Desarrollo

```bash
npm ci
npm test        # tests unitarios
npm run lint    # calidad de código
npm start       # levanta en :8080
```

## Pipeline

El CI (`.github/workflows/ci.yml`) corre en cada push y PR:

```
Compilar → Tests → Calidad → 🛡️ SegFix (escaneo + remediación con IA) → 🚦 Security Gate → Empaquetar → Staging
```

**SegFix** escanea el repo, remedia con IA lo que puede y abre un Pull Request con los fixes. El
**Security Gate** corta el despliegue si quedan vulnerabilidades por encima del umbral (`high` por
defecto). Si un hallazgo es un falso positivo, se excepciona desde la consola de SegFix con
justificación y fecha de revisión, y se vuelve a correr el pipeline.

Requiere el secret `SEGFIX_TOKEN` en el repositorio (token de máquina de SegFix).
