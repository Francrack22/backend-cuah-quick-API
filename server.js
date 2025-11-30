// server.js - Backend Cuah-Quick API

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// ==========================================================
// CONFIGURACIÓN DE MIDDLEWARES Y BASE DE DATOS
// ==========================================================

app.use(cors());
app.use(express.json());

// Conexión a la Base de Datos PostgreSQL
const db = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// ==========================================================
// MIDDLEWARES DE AUTENTICACIÓN Y AUTORIZACIÓN (RBAC)
// ==========================================================

// Middleware 1: Verifica el Token JWT
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: "No autorizado, no se encontró token." });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(401).json({ message: "No autorizado, token fallido o expirado." });
        }
        // Adjuntamos el usuario al request
        req.user = user; 
        next();
    });
};

// Middleware 2: Verifica que el usuario sea 'shop'
const isShop = (req, res, next) => {
    // El rol se verifica desde el token decodificado (req.user)
    if (req.user && req.user.role === 'shop') {
        next();
    } else {
        return res.status(403).json({ message: "Acceso denegado. Se requiere rol de tienda." });
    }
};

// ==========================================================
// RUTA DE REGISTRO
// ==========================================================

app.post('/api/register', async (req, res, next) => {
    try {
        const { full_name, email, password, phone, role, student_id } = req.body;
        
        // 1. VALIDACIÓN DE CAMPOS OBLIGATORIOS
        if (!full_name || !email || !password || !phone || !student_id) {
            return res.status(400).json({ message: "Todos los campos son obligatorios, incluyendo la Matrícula." });
        }
        
        // 2. RESTRICCIÓN DE CORREO ESCOLAR (DOMINIO @ucq.edu.mx)
        const requiredDomain = '@ucq.edu.mx'; 
        if (!email.toLowerCase().endsWith(requiredDomain)) {
            return res.status(400).json({ 
                message: `El registro solo está permitido para correos que terminan en ${requiredDomain}.` 
            });
        }
        
        // 3. VALIDACIÓN DE MATRÍCULA VS. CORREO
        const localPart = email.split('@')[0]; 
        const match = localPart.match(/(\d+)$/); 

        if (match) {
            const matriculaEnCorreo = match[0];
            
            if (matriculaEnCorreo !== student_id) {
                return res.status(400).json({ 
                    message: "La matrícula proporcionada no coincide con los números de tu correo institucional." 
                });
            }
        } else {
            return res.status(400).json({ 
                message: "Formato de correo institucional incorrecto. Debe contener la matrícula." 
            });
        }
        
        // 4. CONTINUAR CON EL PROCESO NORMAL 
        // Nota: Aseguramos que los usuarios nuevos se registren como 'client', 
        // para que solo la tienda pueda asignar el rol 'shop' manualmente.
        const finalRole = 'client'; 
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const result = await db.query(
            `INSERT INTO users (full_name, email, password_hash, phone, role, student_id)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id, full_name, email, role, student_id`,
            [full_name, email, hashedPassword, phone, finalRole, student_id]
        );

        const newUser = result.rows[0];
        
        const token = jwt.sign(
            { id: newUser.id, role: newUser.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(201).json({ 
            message: "Registro exitoso.", 
            token,
            user: {
                id: newUser.id,
                full_name: newUser.full_name,
                email: newUser.email,
                role: newUser.role,
                student_id: newUser.student_id 
            }
        });

    } catch (error) {
        if (error.code === '23505') { 
            return res.status(400).json({ message: "El correo electrónico o la matrícula ya están registrados." });
        }
        console.error("Error en el registro:", error);
        res.status(500).json({ message: "Error interno del servidor." });
    }
});

// ==========================================================
// RUTA DE LOGIN
// ==========================================================

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ message: "Credenciales inválidas." });
        }

        const token = jwt.sign(
            { id: user.id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(200).json({ 
            message: "Inicio de sesión exitoso.", 
            token,
            user: {
                id: user.id,
                full_name: user.full_name,
                email: user.email,
                role: user.role,
            }
        });

    } catch (error) {
        console.error("Error en el login:", error);
        res.status(500).json({ message: "Error interno del servidor." });
    }
});

// ==========================================================
// RUTA DE PEDIDOS PARA LA TIENDA (PROTEGIDA POR ROL)
// ==========================================================
// Endpoint que usa los dos middlewares: 1. Autenticación (verifyToken) y 2. Autorización (isShop)
app.get('/api/shop/orders', verifyToken, isShop, async (req, res) => {
    try {
        // Asumiendo que tienes una tabla 'orders'
        const result = await db.query(`
            SELECT 
                o.id,
                o.status,
                o.total_amount,
                o.created_at,
                u.full_name AS client_name,
                u.phone AS client_phone
            FROM orders o
            JOIN users u ON o.user_id = u.id
            WHERE o.status = 'pending'
            ORDER BY o.created_at ASC
        `);

        res.status(200).json({ 
            message: "Pedidos pendientes obtenidos exitosamente.",
            orders: result.rows
        });

    } catch (error) {
        console.error("Error al obtener pedidos:", error);
        res.status(500).json({ message: "Error interno del servidor al obtener pedidos." });
    }
});

// ==========================================================
// RUTA DE ÓRDENES DEL CLIENTE (EJEMPLO)
// ==========================================================

app.post('/api/orders', verifyToken, async (req, res) => {
    // Aquí iría la lógica para que el cliente cree una orden.
    // Usaría req.user.id para saber qué usuario está creando la orden.
    res.status(201).json({ message: "Ruta de creación de orden (pendiente de implementación)." });
});

// ==========================================================
// INICIO DEL SERVIDOR
// ==========================================================

app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});
