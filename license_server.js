// ==================== BACKEND DE VALIDAÇÃO DE LICENÇAS ====================
// Exemplo em Node.js + Express + SQLite
// 
// Para usar:
// 1. Instale: npm install express sqlite3 body-parser cors
// 2. Execute: node license_server.js
// 3. Configure o frontend para apontar para este servidor

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Banco de dados
const db = new sqlite3.Database('./licenses.db', (err) => {
    if (err) {
        console.error('Erro ao conectar ao banco de dados:', err);
    } else {
        console.log('✅ Conectado ao banco de dados');
        initDatabase();
    }
});

// Inicializar banco de dados
function initDatabase() {
    db.run(`
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE NOT NULL,
            client_name TEXT,
            client_email TEXT,
            license_type TEXT,
            duration_days INTEGER,
            created_at INTEGER,
            activated_at INTEGER,
            expires_at INTEGER,
            device_fingerprint TEXT,
            status TEXT DEFAULT 'unused',
            max_devices INTEGER DEFAULT 1,
            notes TEXT
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS activations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT,
            device_fingerprint TEXT,
            activated_at INTEGER,
            ip_address TEXT,
            user_agent TEXT,
            FOREIGN KEY (license_key) REFERENCES licenses(license_key)
        )
    `);

    console.log('✅ Banco de dados inicializado');
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

        db.run(`
            INSERT INTO licenses (
                license_key, client_name, client_email, license_type,
                duration_days, created_at, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [
            licenseKey,
            clientName || 'Não especificado',
            clientEmail || 'Não especificado',
            licenseType || 'lifetime',
            durationDays || 0,
            createdAt,
            notes || ''
        ], function(err) {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: 'Erro ao gerar licença',
                    error: err.message
                });
            }

            res.json({
                success: true,
                data: {
                    licenseKey: licenseKey,
                    clientName: clientName,
                    clientEmail: clientEmail,
                    createdAt: createdAt
                }
            });
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
        db.get(
            'SELECT * FROM licenses WHERE license_key = ?',
            [key],
            async (err, license) => {
                if (err || !license) {
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
                        db.run(
                            'UPDATE licenses SET status = ? WHERE license_key = ?',
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

                db.run(`
                    UPDATE licenses 
                    SET status = ?,
                        activated_at = ?,
                        expires_at = ?,
                        device_fingerprint = ?
                    WHERE license_key = ?
                `, [
                    'active',
                    activatedAt,
                    expiresAt,
                    hashFingerprint(fingerprint),
                    key
                ], (err) => {
                    if (err) {
                        return res.json({
                            valid: false,
                            message: 'Erro ao ativar licença'
                        });
                    }

                    // Registrar ativação
                    db.run(`
                        INSERT INTO activations (
                            license_key, device_fingerprint, activated_at,
                            ip_address, user_agent
                        ) VALUES (?, ?, ?, ?, ?)
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
                });
            }
        );

    } catch (error) {
        res.status(500).json({
            valid: false,
            message: error.message
        });
    }
});

// 3. Listar Todas as Licenças
app.get('/api/licenses', (req, res) => {
    db.all('SELECT * FROM licenses ORDER BY created_at DESC', (err, rows) => {
        if (err) {
            return res.status(500).json({
                success: false,
                message: 'Erro ao buscar licenças'
            });
        }

        res.json({
            success: true,
            data: rows
        });
    });
});

// 4. Buscar Licença Específica
app.get('/api/licenses/:key', (req, res) => {
    const { key } = req.params;

    db.get(
        'SELECT * FROM licenses WHERE license_key = ?',
        [key],
        (err, row) => {
            if (err || !row) {
                return res.status(404).json({
                    success: false,
                    message: 'Licença não encontrada'
                });
            }

            // Buscar histórico de ativações
            db.all(
                'SELECT * FROM activations WHERE license_key = ?',
                [key],
                (err, activations) => {
                    res.json({
                        success: true,
                        data: {
                            ...row,
                            activations: activations || []
                        }
                    });
                }
            );
        }
    );
});

// 5. Revogar Licença
app.post('/api/licenses/:key/revoke', (req, res) => {
    const { key } = req.params;

    db.run(
        'UPDATE licenses SET status = ? WHERE license_key = ?',
        ['revoked', key],
        function(err) {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: 'Erro ao revogar licença'
                });
            }

            if (this.changes === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Licença não encontrada'
                });
            }

            res.json({
                success: true,
                message: 'Licença revogada com sucesso'
            });
        }
    );
});

// 6. Excluir Licença
app.delete('/api/licenses/:key', (req, res) => {
    const { key } = req.params;

    db.run(
        'DELETE FROM licenses WHERE license_key = ?',
        [key],
        function(err) {
            if (err) {
                return res.status(500).json({
                    success: false,
                    message: 'Erro ao excluir licença'
                });
            }

            if (this.changes === 0) {
                return res.status(404).json({
                    success: false,
                    message: 'Licença não encontrada'
                });
            }

            // Excluir ativações relacionadas
            db.run('DELETE FROM activations WHERE license_key = ?', [key]);

            res.json({
                success: true,
                message: 'Licença excluída com sucesso'
            });
        }
    );
});

// 7. Estatísticas
app.get('/api/stats', (req, res) => {
    db.get(`
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN status = 'unused' THEN 1 ELSE 0 END) as unused,
            SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
            SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END) as expired,
            SUM(CASE WHEN status = 'revoked' THEN 1 ELSE 0 END) as revoked
        FROM licenses
    `, (err, stats) => {
        if (err) {
            return res.status(500).json({
                success: false,
                message: 'Erro ao buscar estatísticas'
            });
        }

        res.json({
            success: true,
            data: stats
        });
    });
});

// 8. Resetar Licença (Remover fingerprint)
app.post('/api/licenses/:key/reset', (req, res) => {
    const { key } = req.params;

    db.run(`
        UPDATE licenses 
        SET status = 'unused',
            device_fingerprint = NULL,
            activated_at = NULL
        WHERE license_key = ?
    `, [key], function(err) {
        if (err) {
            return res.status(500).json({
                success: false,
                message: 'Erro ao resetar licença'
            });
        }

        if (this.changes === 0) {
            return res.status(404).json({
                success: false,
                message: 'Licença não encontrada'
            });
        }

        res.json({
            success: true,
            message: 'Licença resetada com sucesso'
        });
    });
});

// 9. Resetar Licença - Endpoint compatível com gerador V3
app.post('/api/licenses/reset', (req, res) => {
    const { licenseKey } = req.body;
    
    if (!licenseKey) {
        return res.json({ 
            success: false, 
            error: 'Chave de licença não fornecida' 
        });
    }
    
    db.run(`
        UPDATE licenses 
        SET status = 'unused',
            device_fingerprint = NULL,
            activated_at = NULL,
            expires_at = NULL
        WHERE license_key = ?
    `, [licenseKey], function(err) {
        if (err) {
            console.error('Erro ao resetar licença:', err);
            return res.json({ 
                success: false, 
                error: err.message 
            });
        }
        
        if (this.changes === 0) {
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
    });
});

// ==================== WEBHOOK PARA PAGAMENTOS ====================

// Exemplo de webhook para Stripe
app.post('/webhook/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    // const endpointSecret = 'seu_webhook_secret';

    let event;

    try {
        // Verificar assinatura do webhook
        // event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);

        // Simulação para exemplo
        event = JSON.parse(req.body);

        if (event.type === 'checkout.session.completed') {
            const session = event.data.object;

            // Gerar licença automaticamente
            const licenseKey = generateLicenseKey();
            const createdAt = Date.now();

            db.run(`
                INSERT INTO licenses (
                    license_key, client_email, license_type,
                    duration_days, created_at
                ) VALUES (?, ?, ?, ?, ?)
            `, [
                licenseKey,
                session.customer_email,
                'lifetime',
                0,
                createdAt
            ], (err) => {
                if (!err) {
                    // Enviar email com a licença
                    console.log(`📧 Licença enviada para ${session.customer_email}: ${licenseKey}`);
                }
            });
        }

        res.json({ received: true });

    } catch (err) {
        console.error('Erro no webhook:', err.message);
        res.status(400).send(`Webhook Error: ${err.message}`);
    }
});

// ==================== INICIAR SERVIDOR ====================

app.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🔐 SERVIDOR DE LICENÇAS CADERNO PRO                    ║
║                                                           ║
║   Servidor rodando em: http://localhost:${PORT}           ║
║                                                           ║
║   Endpoints disponíveis:                                  ║
║   • POST   /api/licenses/generate  - Gerar licença       ║
║   • POST   /api/validate           - Validar licença     ║
║   • GET    /api/licenses           - Listar todas        ║
║   • GET    /api/licenses/:key      - Buscar específica   ║
║   • POST   /api/licenses/:key/revoke  - Revogar          ║
║   • POST   /api/licenses/:key/reset   - Resetar (URL)    ║
║   • POST   /api/licenses/reset        - Resetar (Body)   ║
║   • DELETE /api/licenses/:key      - Excluir             ║
║   • GET    /api/stats              - Estatísticas        ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    `);
});

// ==================== TRATAMENTO DE ERROS ====================

process.on('SIGINT', () => {
    console.log('\n🛑 Encerrando servidor...');
    db.close((err) => {
        if (err) {
            console.error('Erro ao fechar banco de dados:', err);
        } else {
            console.log('✅ Banco de dados fechado');
        }
        process.exit(0);
    });
});

// ==================== EXEMPLO DE USO ====================
/*

1. GERAR LICENÇA:
   curl -X POST http://localhost:3000/api/licenses/generate \
   -H "Content-Type: application/json" \
   -d '{
     "clientName": "João Silva",
     "clientEmail": "joao@email.com",
     "licenseType": "lifetime",
     "durationDays": 0,
     "notes": "Cliente VIP"
   }'

2. VALIDAR LICENÇA:
   curl -X POST http://localhost:3000/api/validate \
   -H "Content-Type: application/json" \
   -d '{
     "key": "XXXX-XXXX-XXXX-XXXX",
     "fingerprint": "abc123def456"
   }'

3. LISTAR TODAS:
   curl http://localhost:3000/api/licenses

4. ESTATÍSTICAS:
   curl http://localhost:3000/api/stats

5. REVOGAR:
   curl -X POST http://localhost:3000/api/licenses/XXXX-XXXX-XXXX-XXXX/revoke

*/
