// ==================== BACKEND DE VALIDAÇÃO DE LICENÇAS ====================
// Node.js + Express + PostgreSQL
// 
// Para usar:
// 1. Instale: npm install express pg body-parser cors
// 2. Configure DATABASE_URL no Render
// 3. Execute: node license_server.js

const express = require('express');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Configuração do PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Testar conexão
pool.query('SELECT NOW()', (err, res) => {
    if (err) {
        console.error('❌ Erro ao conectar ao PostgreSQL:', err);
    } else {
        console.log('✅ Conectado ao PostgreSQL:', res.rows[0].now);
        initDatabase();
    }
});

// Inicializar banco de dados
async function initDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS licenses (
                id SERIAL PRIMARY KEY,
                license_key VARCHAR(20) UNIQUE NOT NULL,
                client_name VARCHAR(255),
                client_email VARCHAR(255),
                license_type VARCHAR(50),
                duration_days INTEGER,
                created_at BIGINT,
                activated_at BIGINT,
                expires_at BIGINT,
                device_fingerprint VARCHAR(64),
                status VARCHAR(20) DEFAULT 'unused',
                max_devices INTEGER DEFAULT 1,
                notes TEXT
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS activations (
                id SERIAL PRIMARY KEY,
                license_key VARCHAR(20),
                device_fingerprint VARCHAR(64),
                activated_at BIGINT,
                ip_address VARCHAR(50),
                user_agent TEXT,
                FOREIGN KEY (license_key) REFERENCES licenses(license_key) ON DELETE CASCADE
            )
        `);

        console.log('✅ Tabelas inicializadas');
    } catch (error) {
        console.error('❌ Erro ao inicializar banco:', error);
    }
}

// ==================== FUNÇÕES AUXILIARES ====================

function generateLicenseKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let key = '';
    for (let i = 0; i < 4; i++) {
        for (let j = 0; j < 4; j++) {
            key += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        if (i < 3) key += '-';
    }
    return key;
}

function hashFingerprint(fingerprint) {
    return crypto.createHash('sha256').update(fingerprint).digest('hex');
}

// ==================== ENDPOINTS ====================

// 1. Gerar Nova Licença
app.post('/api/licenses/generate', async (req, res) => {
    try {
        const {
            clientName,
            clientEmail,
            licenseType,
            durationDays,
            notes
        } = req.body;

        const licenseKey = generateLicenseKey();
        const createdAt = Date.now();

        await pool.query(`
            INSERT INTO licenses (
                license_key, client_name, client_email, license_type,
                duration_days, created_at, notes
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        `, [
            licenseKey,
            clientName || 'Não especificado',
            clientEmail || 'Não especificado',
            licenseType || 'lifetime',
            durationDays || 0,
            createdAt,
            notes || ''
        ]);

        res.json({
            success: true,
            data: {
                licenseKey: licenseKey,
                clientName: clientName,
                clientEmail: clientEmail,
                createdAt: createdAt
            }
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// 2. Validar e Ativar Licença
app.post('/api/validate', async (req, res) => {
    try {
        const { key, fingerprint } = req.body;

        if (!key || !fingerprint) {
            return res.json({
                valid: false,
                message: 'Chave ou fingerprint ausente'
            });
        }

        // Buscar licença
        const result = await pool.query(
            'SELECT * FROM licenses WHERE license_key = $1',
            [key]
        );

        const license = result.rows[0];

        if (!license) {
            return res.json({
                valid: false,
                message: 'Licença não encontrada'
            });
        }

        // Verificar se já foi ativada
        if (license.status === 'active') {
            // Verificar se é o mesmo dispositivo
            if (license.device_fingerprint !== hashFingerprint(fingerprint)) {
                return res.json({
                    valid: false,
                    message: 'Licença já ativada em outro dispositivo'
                });
            }

            // Verificar expiração
            if (license.expires_at > 0 && Date.now() > license.expires_at) {
                // Atualizar status
                await pool.query(
                    'UPDATE licenses SET status = $1 WHERE license_key = $2',
                    ['expired', key]
                );

                return res.json({
                    valid: false,
                    message: 'Licença expirada'
                });
            }

            // Retornar dados da licença ativa
            return res.json({
                valid: true,
                data: {
                    key: key,
                    fingerprint: fingerprint,
                    activatedAt: license.activated_at,
                    expiresAt: license.expires_at,
                    user: {
                        name: license.client_name,
                        email: license.client_email
                    }
                }
            });
        }

        // Ativar pela primeira vez
        const activatedAt = Date.now();
        const expiresAt = license.duration_days === 0 ? 0 :
            activatedAt + (license.duration_days * 24 * 60 * 60 * 1000);

        await pool.query(`
            UPDATE licenses 
            SET status = $1,
                activated_at = $2,
                expires_at = $3,
                device_fingerprint = $4
            WHERE license_key = $5
        `, [
            'active',
            activatedAt,
            expiresAt,
            hashFingerprint(fingerprint),
            key
        ]);

        // Registrar ativação
        await pool.query(`
            INSERT INTO activations (
                license_key, device_fingerprint, activated_at,
                ip_address, user_agent
            ) VALUES ($1, $2, $3, $4, $5)
        `, [
            key,
            hashFingerprint(fingerprint),
            activatedAt,
            req.ip,
            req.headers['user-agent']
        ]);

        res.json({
            valid: true,
            data: {
                key: key,
                fingerprint: fingerprint,
                activatedAt: activatedAt,
                expiresAt: expiresAt,
                user: {
                    name: license.client_name,
                    email: license.client_email
                }
            }
        });

    } catch (error) {
        res.status(500).json({
            valid: false,
            message: error.message
        });
    }
});

// 3. Listar Todas as Licenças
app.get('/api/licenses', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM licenses ORDER BY created_at DESC'
        );

        res.json({
            success: true,
            data: result.rows
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// 4. Buscar Licença Específica
app.get('/api/licenses/:key', async (req, res) => {
    try {
        const { key } = req.params;

        const result = await pool.query(
            'SELECT * FROM licenses WHERE license_key = $1',
            [key]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Licença não encontrada'
            });
        }

        // Buscar histórico de ativações
        const activations = await pool.query(
            'SELECT * FROM activations WHERE license_key = $1',
            [key]
        );

        res.json({
            success: true,
            data: {
                ...result.rows[0],
                activations: activations.rows
            }
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// 5. Revogar Licença
app.post('/api/licenses/:key/revoke', async (req, res) => {
    try {
        const { key } = req.params;

        const result = await pool.query(
            'UPDATE licenses SET status = $1 WHERE license_key = $2',
            ['revoked', key]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({
                success: false,
                message: 'Licença não encontrada'
            });
        }

        res.json({
            success: true,
            message: 'Licença revogada com sucesso'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// 6. Excluir Licença
app.delete('/api/licenses/:key', async (req, res) => {
    try {
        const { key } = req.params;

        const result = await pool.query(
            'DELETE FROM licenses WHERE license_key = $1',
            [key]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({
                success: false,
                message: 'Licença não encontrada'
            });
        }

        res.json({
            success: true,
            message: 'Licença excluída com sucesso'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// 7. Estatísticas
app.get('/api/stats', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'unused' THEN 1 ELSE 0 END) as unused,
                SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
                SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END) as expired,
                SUM(CASE WHEN status = 'revoked' THEN 1 ELSE 0 END) as revoked
            FROM licenses
        `);

        res.json({
            success: true,
            data: result.rows[0]
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// 8. Resetar Licença (URL param)
app.post('/api/licenses/:key/reset', async (req, res) => {
    try {
        const { key } = req.params;

        const result = await pool.query(`
            UPDATE licenses 
            SET status = 'unused',
                device_fingerprint = NULL,
                activated_at = NULL,
                expires_at = NULL
            WHERE license_key = $1
        `, [key]);

        if (result.rowCount === 0) {
            return res.json({
                success: false,
                message: 'Licença não encontrada'
            });
        }

        console.log(`✅ Licença resetada: ${key}`);
        res.json({
            success: true,
            message: 'Licença resetada com sucesso'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// 9. Resetar Licença (Body) - Compatível com gerador V3
app.post('/api/licenses/reset', async (req, res) => {
    try {
        const { licenseKey } = req.body;
        
        if (!licenseKey) {
            return res.json({ 
                success: false, 
                error: 'Chave de licença não fornecida' 
            });
        }
        
        const result = await pool.query(`
            UPDATE licenses 
            SET status = 'unused',
                device_fingerprint = NULL,
                activated_at = NULL,
                expires_at = NULL
            WHERE license_key = $1
        `, [licenseKey]);
        
        if (result.rowCount === 0) {
            return res.json({ 
                success: false, 
                error: 'Licença não encontrada' 
            });
        }
        
        console.log(`✅ Licença resetada: ${licenseKey}`);
        res.json({ 
            success: true, 
            message: 'Licença resetada com sucesso' 
        });
    } catch (error) {
        console.error('Erro ao resetar licença:', error);
        res.json({ 
            success: false, 
            error: error.message 
        });
    }
});

// ==================== INICIAR SERVIDOR ====================

app.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🔐 SERVIDOR DE LICENÇAS CADERNO PRO                    ║
║   💾 Banco: PostgreSQL (Persistente)                     ║
║                                                           ║
║   Servidor rodando em: http://localhost:${PORT}           ║
║                                                           ║
║   Endpoints disponíveis:                                  ║
║   • POST   /api/licenses/generate     - Gerar licença    ║
║   • POST   /api/validate              - Validar          ║
║   • GET    /api/licenses              - Listar todas     ║
║   • GET    /api/licenses/:key         - Buscar           ║
║   • POST   /api/licenses/:key/revoke  - Revogar          ║
║   • POST   /api/licenses/:key/reset   - Resetar (URL)    ║
║   • POST   /api/licenses/reset        - Resetar (Body)   ║
║   • DELETE /api/licenses/:key         - Excluir          ║
║   • GET    /api/stats                 - Estatísticas     ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    `);
});

// ==================== TRATAMENTO DE ERROS ====================

process.on('SIGINT', async () => {
    console.log('\n🛑 Encerrando servidor...');
    await pool.end();
    console.log('✅ Conexão com PostgreSQL fechada');
    process.exit(0);
});

// ==================== HEALTH CHECK ====================

app.get('/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({
            status: 'healthy',
            database: 'connected',
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({
            status: 'unhealthy',
            database: 'disconnected',
            error: error.message
        });
    }
});
