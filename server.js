// =================================================================
// 1. IMPORTACIONES Y CONFIGURACIÓN INICIAL
// =================================================================
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Obtener las variables de entorno de Render
const PORT = process.env.PORT || 3000; 

// ¡CRÍTICO! Leer la clave de las variables de entorno de Render
// (Debe coincidir con la variable JWT_SECRET que pusiste en el panel de Render)
const JWT_SECRET = process.env.JWT_SECRET; 

// Configuración de la aplicación Express
const app = express();

// Middlewares globales
app.use(cors()); 
app.use(express.json()); // Permite a Express leer JSON en el cuerpo de las peticiones POST

// =================================================================
// 2. CONEXIÓN A LA BASE DE DATOS (SOLUCIÓN SSL DEFINITIVA)
// =================================================================
const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: 25060, // Puerto de DigitalOcean
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    // La verificación SSL se gestiona por la variable de entorno NODE_TLS_REJECT_UNAUTHORIZED=0 en Render
    // Por eso se omite el objeto 'ssl' aquí.
};

let connection;

async function connectDB() {
    // Verificar si la clave secreta está definida antes de intentar el despliegue
    if (!JWT_SECRET) {
        console.error("❌ ERROR CRÍTICO: La variable de entorno JWT_SECRET no está definida.");
        process.exit(1); 
    }

    try {
        connection = await mysql.createPool(dbConfig);
        console.log('✅ Conectado a DigitalOcean');
    } catch (error) {
        console.error('❌ Error al conectar a la base de datos:', error);
        process.exit(1); 
    }
}

// =================================================================
// 3. MIDDLEWARE DE AUTORIZACIÓN (PROTECCIÓN DE RUTAS)
// =================================================================
const protect = (req, res, next) => {
    let token;
    
    // Obtener el token del encabezado: Authorization: Bearer <token>
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        // Separa "Bearer" de "<token>" y toma el token
        token = req.headers.authorization.split(' ')[1]; 
    }

    if (!token) {
        return res.status(401).send({ message: 'No autorizado, no se encontró token.' });
    }

    try {
        // Verificar y decodificar el token usando la JWT_SECRET
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // Adjuntamos id, email y role al request
        next(); 
    } catch (error) {
        // Este error ocurre si el token está incompleto, malformado o si la JWT_SECRET no coincide
        console.error('Error de token:', error);
        return res.status(401).send({ message: 'No autorizado, token fallido o expirado.' });
    }
};

// =================================================================
// 4. RUTAS DE LA API
// =================================================================

// Ruta de PRUEBA (pública)
app.get('/', (req, res) => {
    res.send('API CUAH-QUICK funcionando. Accede a /api/products para ver el menú.');
});


// 4.1 RUTA PÚBLICA: Obtener Productos
app.get('/api/products', async (req, res) => {
    try {
        // Asume que la tabla 'products' existe y tiene el campo 'is_available'
        const query = 'SELECT * FROM products WHERE is_available = 1';
        const [products] = await connection.query(query);
        
        res.status(200).json(products);
    } catch (error) {
        console.error('Error al obtener productos:', error);
        res.status(500).send({ message: 'Error interno del servidor al obtener productos.' });
    }
});


// 4.2 RUTA PÚBLICA: Registro de Usuario
app.post('/api/register', async (req, res) => {
    const { full_name, email, password, phone, role } = req.body;

    if (!full_name || !email || !password) {
        return res.status(400).send({ message: 'Nombre completo, email y contraseña son obligatorios.' });
    }

    try {
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);
        
        const query = `
            INSERT INTO users (full_name, email, password_hash, phone, role) 
            VALUES (?, ?, ?, ?, ?)
        `;
        const userRole = role || 'client'; 

        await connection.query(query, [full_name, email, passwordHash, phone || null, userRole]);

        res.status(201).send({ message: 'Usuario registrado exitosamente.' });

    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).send({ message: 'Este correo electrónico ya está registrado.' });
        }
        console.error('Error al registrar usuario:', error); 
        res.status(500).send({ message: 'Error interno del servidor.' });
    }
});


// 4.3 RUTA PÚBLICA: Inicio de Sesión
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send({ message: 'Email y contraseña son obligatorios.' });
    }

    try {
        const query = 'SELECT id, email, full_name, role, password_hash FROM users WHERE email = ?';
        const [results] = await connection.query(query, [email]);
        const user = results[0];

        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).send({ message: 'Credenciales inválidas.' });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '1h' } // Token expira en 1 hora
        );

        res.status(200).send({
            message: 'Inicio de sesión exitoso.',
            token: token,
            user: { id: user.id, full_name: user.full_name, email: user.email, role: user.role }
        });

    } catch (error) {
        console.error('Error al iniciar sesión:', error);
        res.status(500).send({ message: 'Error interno del servidor.' });
    }
});


// 4.4 RUTA PRIVADA (PROTEGIDA): Crear una Orden
// Esta ruta requiere un JWT válido en el encabezado 'Authorization'
app.post('/api/orders', protect, async (req, res) => {
    // req.user.id se obtiene del token gracias al middleware 'protect'
    const user_id = req.user.id; 
    const { shop_id, total_amount, building, classroom, delivery_notes } = req.body;
    
    // Asume que la tabla 'orders' ya fue creada en DigitalOcean
    if (!shop_id || !total_amount || !user_id) {
        return res.status(400).send({ message: 'Faltan datos requeridos para la orden.' });
    }

    try {
        const query = `
            INSERT INTO orders (user_id, shop_id, total_amount, status, building, classroom, delivery_notes) 
            VALUES (?, ?, ?, 'pending', ?, ?, ?)
        `;
        
        await connection.query(query, [
            user_id, 
            shop_id, 
            total_amount, 
            building, 
            classroom, 
            delivery_notes
        ]);

        res.status(201).send({ message: 'Orden creada exitosamente.' });

    } catch (error) {
        // Si no tienes la tabla orders creada, aquí fallará con ER_NO_SUCH_TABLE
        console.error('Error al crear orden:', error);
        res.status(500).send({ message: 'Error interno del servidor.' });
    }
});

// =================================================================
// 5. INICIO DEL SERVIDOR
// =================================================================
connectDB().then(() => {
    app.listen(PORT, () => {
        console.log(`🚀 Servidor listo en puerto ${PORT}`);
    });
});