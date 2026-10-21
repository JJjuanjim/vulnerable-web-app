/**
 * ============================================================================
 * PROYECTO: APLICACIÓN WEB VULNERABLE PARA ANÁLISIS ESTÁTICO (SAST)
 * HERRAMIENTAS: SonarQube / SonarCloud
 * OBJETIVO: Detección forzada de más de 10 vulnerabilidades de seguridad y bugs
 * ============================================================================
 */

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const crypto = require('crypto');
const http = require('http');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================================
// VULNERABILIDAD 1: Credenciales Quemadas y Secretos en Código Duro (Hardcoded Credentials)
// CWE-798 / OWASP A07:2021 - Identification and Authentication Failures
// SonarQube Rules: javascript:S2068 (Hard-coded credentials), javascript:S6290 (Hard-coded secrets)
// ============================================================================

// 1.1 Contraseñas quemadas clásicas más expuestas en la industria (Diccionario por defecto)
const DEFAULT_BURNED_PASSWORDS = [
    { username: "admin", password: "password123", role: "SuperAdministrador" },
    { username: "root", password: "toor", role: "RootGlobal" },
    { username: "user_test", password: "123456", role: "Operador" },
    { username: "db_admin", password: "admin", role: "DBA" },
    { username: "cisco_switch", password: "cisco", role: "NetworkManager" },
    { username: "servidor_backup", password: "Password2026!*", role: "BackupSys" }
];

// 1.2 Cadenas de conexión de bases de datos con usuarios y contraseñas expuestas
const POSTGRES_PROD_URL = "postgres://postgres:admin1234@192.168.1.100:5432/clientes_produccion";
const MONGO_CLUSTER_URI = "mongodb+srv://admin:SuperSecretPassword2026!#@cluster0.mongodb.net/finanzas";

// 1.3 Claves de API y tokens de infraestructura en código duro
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI_MOCK_AWS_KEY_7MDENG_EXAMPLEKEY";
const STRIPE_SECRET_KEY = "sk_test_51NzQ8LCI_MOCK_STRIPE_KEY_abcdefghijklmnop";
const GITHUB_PERSONAL_TOKEN = "ghp_MOCK_GITHUB_TOKEN_1234567890abcdefghijklmno";
const JWT_SECRET = "my_hardcoded_jwt_super_secret_key_12345";

// Endpoint para validar si una credencial ingresada coincide con las quemadas
app.post('/api/check-burned-credentials', (req, res) => {
    const { username, password } = req.body;
    
    // Comparación contra la lista quemada en código
    const found = DEFAULT_BURNED_PASSWORDS.find(u => u.username === username && u.password === password);
    
    if (found) {
        return res.json({
            status: "vulnerable",
            message: "¡ALERTA! Inicio de sesion exitoso con credencial por defecto / quemada.",
            account: found,
            warning: "Esta cuenta utiliza contrasenas publicas conocidas por atacantes.",
            databaseConnectionSample: POSTGRES_PROD_URL
        });
    }

    return res.status(401).json({
        status: "safe",
        message: "Credencial no coincide con el diccionario de contrasenas quemadas.",
        burnedDictionaryCount: DEFAULT_BURNED_PASSWORDS.length
    });
});

// Endpoint que expone la lista de secretos quemados para auditoría
app.get('/api/view-burned-secrets', (req, res) => {
    res.json({
        advertencia: "SECRETOS EXPUESTOS EN CODIGO FUENTE (CWE-798)",
        dbConnections: {
            postgres: POSTGRES_PROD_URL,
            mongodb: MONGO_CLUSTER_URI
        },
        apiKeys: {
            awsKey: AWS_ACCESS_KEY_ID,
            awsSecret: AWS_SECRET_ACCESS_KEY,
            stripe: STRIPE_SECRET_KEY,
            githubToken: GITHUB_PERSONAL_TOKEN
        },
        cuentasPorDefecto: DEFAULT_BURNED_PASSWORDS
    });
});

// ============================================================================
// VULNERABILIDAD 2: Configuración Insegura de CORS (CORS Wildcard with Credentials)
// CWE-942 / OWASP A05:2021 - Security Misconfiguration
// SonarQube Rule: javascript:S5122
// ============================================================================
app.use((req, res, next) => {
    // Permite que cualquier origen acceda con credenciales habilitadas
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Credentials", "true");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
});

// ============================================================================
// VULNERABILIDAD 3: Inyección SQL (SQL Injection - SQLi)
// CWE-89 / OWASP A03:2021 - Injection
// SonarQube Rule: javascript:S3649, javascript:S2077
// ============================================================================
app.post('/api/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    // Concatenación directa sin sanitización ni consultas preparadas
    const rawSqlQuery = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
    console.log("[SQL Query]:", rawSqlQuery);

    // Simulación de respuesta vulnerable
    if (username && username.includes("' OR '1'='1")) {
        return res.json({ status: "success", message: "Autenticado como Administrador mediante SQL Injection", user: "admin", query: rawSqlQuery });
    }
    return res.status(401).json({ status: "failed", message: "Credenciales incorrectas", query: rawSqlQuery });
});

// ============================================================================
// VULNERABILIDAD 4: Inyección de Comandos del Sistema Operativo (Command Injection / RCE)
// CWE-78 / OWASP A03:2021 - Injection
// SonarQube Rule: javascript:S2076, javascript:S5334
// ============================================================================
app.get('/api/ping', (req, res) => {
    const targetHost = req.query.host || "127.0.0.1";

    // Entrada del usuario concatenada directamente a exec de bash/cmd
    const cmd = "ping -c 2 " + targetHost;
    console.log("[Ejecutando comando del SO]:", cmd);

    exec(cmd, (error, stdout, stderr) => {
        if (error) {
            return res.json({ error: error.message, output: stderr });
        }
        res.json({ output: stdout, command: cmd });
    });
});

// ============================================================================
// VULNERABILIDAD 5: Cross-Site Scripting Reflejado (Reflected XSS)
// CWE-79 / OWASP A03:2021 - Injection
// SonarQube Rule: javascript:S5131, javascript:S5247
// ============================================================================
app.get('/api/search', (req, res) => {
    const query = req.query.q || "Sin busqueda";

    // Envío de HTML sin escapar directamente a la respuesta
    res.setHeader('Content-Type', 'text/html');
    res.send("<html><body><h2>Resultados de busqueda para: " + query + "</h2><p>No se encontraron registros.</p></body></html>");
});

// ============================================================================
// VULNERABILIDAD 6: Salto de Directorio / Lectura Arbitraria de Archivos (Path Traversal)
// CWE-22 / OWASP A01:2021 - Broken Access Control
// SonarQube Rule: javascript:S2083
// ============================================================================
app.get('/api/view-file', (req, res) => {
    const filename = req.query.file || "public/index.html";

    // Concatenación directa que permite usar ../../ para escapar del directorio
    const filePath = path.join(__dirname, filename);
    console.log("[Leyendo archivo]:", filePath);

    try {
        const fileContent = fs.readFileSync(filePath, 'utf8');
        res.send("<pre>" + fileContent + "</pre>");
    } catch (err) {
        res.status(500).send("Error al leer archivo: " + err.message);
    }
});

// ============================================================================
// VULNERABILIDAD 7: Criptografía Débil / Algoritmo Roto (Weak Cryptographic Hash - MD5/SHA1)
// CWE-327 / CWE-328 / OWASP A02:2021 - Cryptographic Failures
// SonarQube Rule: javascript:S2070, javascript:S4790
// ============================================================================
app.post('/api/hash-password', (req, res) => {
    const password = req.body.password || "Password123";

    // Uso de MD5 (prohibido para contraseñas y criptografía moderna)
    const md5Hash = crypto.createHash('md5').update(password).digest('hex');

    // Uso de SHA1 (también débil y colisionable)
    const sha1Hash = crypto.createHash('sha1').update(password).digest('hex');

    res.json({
        passwordOriginal: password,
        hashMD5: md5Hash,
        hashSHA1: sha1Hash,
        warning: "MD5 y SHA1 no son seguros para hashing de credenciales"
    });
});

// ============================================================================
// VULNERABILIDAD 8: Redirección Abierta (Open Redirect)
// CWE-601 / OWASP A01:2021 - Broken Access Control
// SonarQube Rule: javascript:S5146
// ============================================================================
app.get('/api/redirect', (req, res) => {
    const targetUrl = req.query.url;

    // Redirección directa sin validar si el dominio es confiable
    if (targetUrl) {
        return res.redirect(targetUrl);
    }
    res.status(400).send("Falta el parametro url");
});

// ============================================================================
// VULNERABILIDAD 9: Falsificación de Petición del Lado del Servidor (SSRF)
// CWE-918 / OWASP A10:2021 - Server-Side Request Forgery
// SonarQube Rule: javascript:S5144
// ============================================================================
app.get('/api/fetch-remote', (req, res) => {
    const targetUrl = req.query.url || "http://127.0.0.1:3000";

    // Petición HTTP interna a cualquier URL solicitada por el cliente
    http.get(targetUrl, (response) => {
        let data = '';
        response.on('data', (chunk) => { data += chunk; });
        response.on('end', () => { res.json({ fetchedUrl: targetUrl, data: data.substring(0, 300) }); });
    }).on('error', (err) => {
        res.status(500).json({ error: err.message });
    });
});

// ============================================================================
// VULNERABILIDAD 10: Token JWT Inseguro / Algoritmo 'none' y Clave Débil
// CWE-330 / CWE-327 / OWASP A07:2021
// SonarQube Rule: javascript:S6730, javascript:S6731
// ============================================================================
app.post('/api/generate-token', (req, res) => {
    const userData = { username: req.body.username || "invitado", role: "user" };

    // Firma con clave débil hardcodeada y sin tiempo de expiración
    const token = jwt.sign(userData, JWT_SECRET, { algorithm: 'HS256' });

    // Creación de token sin firma (algoritmo 'none')
    const insecureToken = jwt.sign(userData, "", { algorithm: 'none' });

    res.json({ tokenHS256: token, tokenNone: insecureToken });
});

// ============================================================================
// VULNERABILIDAD 11: Contaminación de Prototipos / Deserialización Insegura
// CWE-1321 / CWE-502 / OWASP A08:2021 - Software and Data Integrity Failures
// SonarQube Rule: javascript:S5883
// ============================================================================
app.post('/api/merge-settings', (req, res) => {
    const userPayload = req.body;
    let targetConfig = {};

    // Insecure Object merge vulnerable a Prototype Pollution
    for (let key in userPayload) {
        targetConfig[key] = userPayload[key];
        // Si el payload tiene __proto__, se contamina el prototipo global
        if (key === "__proto__") {
            Object.prototype[key] = userPayload[key];
        }
    }
    res.json({ status: "Configuracion aplicada", config: targetConfig });
});


// ============================================================================
// BUGS Y CODE SMELLS INTENCIONALES (Para cumplir el requisito de detección de bugs)
// SonarQube Rules: javascript:S1994, javascript:S1763, javascript:S1862, javascript:S1656
// ============================================================================

// BUG 1: Asignación dentro de una condición lógica (debería ser ===)
function checkUserRole(user) {
    let role = "guest";
    // BUG: Asignación '=' en vez de comparación '==='
    if (role = "admin") {
        console.log("Acceso concedido");
    }
    return role;
}

// BUG 2: Código inalcanzable (Dead Code) después de un return
function calculateSecurityScore() {
    let score = 100;
    return score;
    // BUG: Código muerto que nunca se ejecuta
    score = score - 50;
    console.log("Puntaje recalculado:", score);
}

// BUG 3: Ramas idénticas en estructura condicional (Identical if-else branches)
function validateIpAddress(ip) {
    if (ip === "127.0.0.1") {
        return "IP Valida";
    } else {
        // BUG: Mismo resultado que la rama if
        return "IP Valida";
    }
}

// BUG 4: Auto-asignación inútil (Self-assignment)
function sanitizeText(input) {
    let text = input;
    // BUG: Asignar una variable a sí misma
    text = text;
    return text;
}

// BUG 5: Desreferencia potencial de null / undefined (Null Pointer Exception)
function getUserEmail(user) {
    // BUG: Acceso a propiedad de objeto sin verificar si user o profile existen
    return user.profile.contact.email;
}

// Endpoint de prueba que ejecuta los bugs para visualizarlos
app.get('/api/test-bugs', (req, res) => {
    const roleResult = checkUserRole({});
    const scoreResult = calculateSecurityScore();
    const ipResult = validateIpAddress("192.168.1.1");
    const sanitized = sanitizeText("Prueba");

    res.json({
        bug1_AsignacionEnIf: roleResult,
        bug2_DeadCodeScore: scoreResult,
        bug3_IdenticalBranches: ipResult,
        bug4_SelfAssignment: sanitized,
        message: "Bugs analizados con exito"
    });
});

// Iniciar servidor
app.listen(PORT, () => {
    console.log(`===================================================`);
    console.log(` Servidor Vulnerable SAST activo en http://localhost:${PORT}`);
    console.log(` Listo para escanear con SonarQube / SonarCloud`);
    console.log(`===================================================`);
});
