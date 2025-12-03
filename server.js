// server.js - Backend Cuah-Quick API (CORREGIDO PARA SSL DE DIGITALOCEAN)

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// ==========================================================
// CONFIGURACIÓN CORS
// ==========================================================
const corsOptions = {
    origin: 'https://francrack22.github.io', 
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    optionsSuccessStatus: 204
};
app.use(cors(corsOptions));
app.use(express.json());

// ==========================================================
// CONEXIÓN ROBUSTA A BASE DE DATOS (FIX SSL)
// ==========================================================

let pool;

try {
    // 1. Verificamos que la URL exista
    if (!process.env.DATABASE_URL) {
        throw new Error("DATABASE_URL no está definida en las variables de entorno.");
    }

    // 2. Parseamos la URL para configurarla manualmente
    // Esto evita el error de "ssl-mode" ignorado
    const dbUrl = new URL(process.env.DATABASE_URL);

    const dbConfig = {
        host: dbUrl.hostname,
        user: dbUrl.username,
        password: dbUrl.password,
        database: dbUrl.pathname.slice(1), // Quitamos la barra inicial '/'
        port: dbUrl.port || 25060,
        ssl: {
            rejectUnauthorized: false // IMPORTANTE: Permite la conexión SSL con DigitalOcean
        },
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0
    };

    // 3. Creamos el pool con la configuración manual
    pool = mysql.createPool(dbConfig);
    
    // 4. Prueba de conexión inmediata para ver si funciona al arrancar
    pool.getConnection()
        .then(connection => {
            console.log("✅ ¡CONEXIÓN EXITOSA A LA BASE DE DATOS!");
            connection.release();
        })
        .catch(err => {
            console.error("❌ ERROR FATAL AL CONECTAR A LA BD:", err.message);
        });

} catch (error) {
    console.error("❌ Error configurando la base de datos:", error.message);
}

// ==========================================================
// MIDDLEWARES
// ==========================================================

const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ message: "No autorizado, no se encontró token." });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(401).json({ message: "No autorizado, token inválido." });
        req.user = user; 
        next();
    });
};

const isShop = (req, res, next) => {
    if (req.user && req.user.role === 'shop') next();
    else res.status(403).json({ message: "Acceso denegado. Rol de tienda requerido." });
};

// ==========================================================
// RUTAS
// ==========================================================

// --- REGISTRO (Con logs para depuración) ---
app.post('/api/register', async (req, res) => {
    console.log("📩 Solicitud de registro recibida:", req.body.email); // LOG

    try {
        const { full_name, email, password, phone, student_id } = req.body;
        
        if (!full_name || !email || !password || !phone || !student_id) {
            return res.status(400).json({ message: "Todos los campos son obligatorios." });
        }
        
        const requiredDomain = '@ucq.edu.mx'; 
        if (!email.toLowerCase().endsWith(requiredDomain)) {
            return res.status(400).json({ message: `Solo correos ${requiredDomain} permitidos.` });
        }
        
        const localPart = email.split('@')[0]; 
        const match = localPart.match(/(\d+)$/); 
        if (!match || match[0] !== student_id) {
            return res.status(400).json({ message: "La matrícula no coincide con el correo." });
        }
        
        const finalRole = 'client'; 
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Ejecución SQL
        const [result] = await pool.execute(
            `INSERT INTO users (full_name, email, password_hash, phone, role, student_id)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [full_name, email, hashedPassword, phone, finalRole, student_id]
        );

        console.log("✅ Usuario registrado con ID:", result.insertId); // LOG ÉXITO

        const newUser = { id: result.insertId, full_name, email, role: finalRole, student_id };
        const token = jwt.sign({ id: newUser.id, role: newUser.role }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.status(201).json({ message: "Registro exitoso.", token, user: newUser });

    } catch (error) {
        console.error("❌ ERROR EN EL REGISTRO:", error); // LOG ERROR
        if (error.code === 'ER_DUP_ENTRY') { 
            return res.status(400).json({ message: "El correo o matrícula ya están registrados." });
        }
        res.status(500).json({ message: "Error interno del servidor.", error: error.message });
    }
});

// --- LOGIN ---
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        const user = rows[0];

        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ message: "Credenciales inválidas." });
        }

        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ 
            message: "Inicio de sesión exitoso.", 
            token, 
            user: { id: user.id, full_name: user.full_name, email: user.email, role: user.role, name: user.full_name }
        });
    } catch (error) {
        console.error("Error en login:", error);
        res.status(500).json({ message: "Error interno." });
    }
});

// --- MENÚ ---
app.get('/api/menu', async (req, res) => {
    try {
        const menu = [
            { id: 1, name: "Café Americano", price: 25.00 },
            { id: 2, name: "Latte Frío", price: 35.00 },
            { id: 3, name: "Jugo Verde", price: 40.00 },
            { id: 4, name: "Sándwich de Pavo", price: 55.00 },
            { id: 5, name: "Muffin de Chocolate", price: 28.00 }
        ];
        res.status(200).json({ message: "Menú obtenido.", products: menu });
    } catch (error) {
        res.status(500).json({ message: "Error al obtener menú." });
    }
});

// --- CREAR ORDEN ---
app.post('/api/orders', verifyToken, async (req, res) => {
    const user_id = req.user.id; 
    const { shop_id, total_amount, building, classroom, delivery_notes } = req.body;
    
    if (!shop_id || !total_amount || !building || !classroom) {
        return res.status(400).json({ message: "Faltan datos obligatorios." });
    }

    try {
        const status = 'pending';
        const [result] = await pool.execute(
            `INSERT INTO orders (user_id, shop_id, total_amount, building, classroom, delivery_notes, status)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [user_id, shop_id, total_amount, building, classroom, delivery_notes || '', status]
        );
        res.status(201).json({ message: "Orden creada.", order_id: result.insertId });
    } catch (error) {
        console.error("Error creando orden:", error);
        res.status(500).json({ message: "Error al crear orden." });
    }
});

// --- VER ORDENES (TIENDA) ---
app.get('/api/shop/orders', verifyToken, isShop, async (req, res) => {
    try {
        const [orders] = await pool.execute(`
            SELECT o.id, o.status, o.total_amount, o.created_at, u.full_name AS client_name, u.phone AS client_phone, o.building, o.classroom, o.delivery_notes
            FROM orders o JOIN users u ON o.user_id = u.id
            WHERE o.status IN ('pending', 'preparing', 'ready') ORDER BY o.created_at ASC
        `);
        res.status(200).json({ message: "Pedidos obtenidos.", orders: orders });
    } catch (error) {
        console.error("Error obteniendo pedidos:", error);
        res.status(500).json({ message: "Error al obtener pedidos." });
    }
});

// --- ACTUALIZAR ORDEN (TIENDA) ---
app.put('/api/shop/orders/:id', verifyToken, isShop, async (req, res) => {
    const orderId = req.params.id;
    const { status } = req.body;
    const validStatuses = ['preparing', 'ready', 'delivered', 'cancelled'];

    if (!status || !validStatuses.includes(status)) return res.status(400).json({ message: "Estado inválido." });

    try {
        const [result] = await pool.execute(`UPDATE orders SET status = ? WHERE id = ?`, [status, orderId]);
        if (result.affectedRows === 0) return res.status(404).json({ message: "Pedido no encontrado." });
        res.status(200).json({ message: `Pedido #${orderId} actualizado a ${status}.` });
    } catch (error) {
        console.error("Error actualizando orden:", error);
        res.status(500).json({ message: "Error al actualizar." });
    }
});

app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});
