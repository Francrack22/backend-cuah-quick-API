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

// Configuración de CORS para permitir solicitudes desde GitHub Pages
app.use(cors());

// Middleware para parsear JSON
app.use(express.json());

// Conexión a la Base de Datos PostgreSQL (usando variables de Render)
const db = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Necesario para algunas configuraciones de hosting como Render
    }
});

// Middleware de verificación de Token JWT (Necesario para /orders)
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    // El formato es "Bearer <token>"
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: "No autorizado, no se encontró token." });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            // Esto maneja token expirado o inválido
            return res.status(401).json({ message: "No autorizado, token fallido o expirado." });
        }
        // Adjuntamos el usuario al request para usarlo en la ruta
        req.user = user; 
        next();
    });
};

// ==========================================================
// RUTA DE REGISTRO (CORREGIDA CON MATRÍCULA Y VALIDACIÓN)
// ==========================================================

app.post('/api/register', async (req, res, next) => {
    try {
        const { full_name, email, password, phone, role, student_id } = req.body;
        
        // 1. VALIDACIÓN DE CAMPOS OBLIGATORIOS
        if (!full_name || !email || !password || !phone || !student_id) {
            return res.status(400).json({ message: "Nombre completo, email, contraseña, teléfono y matrícula son obligatorios." });
        }
        
        // 2. RESTRICCIÓN DE CORREO ESCOLAR (
        const requiredDomain = '@ucq.edu.mx'; 
        if (!email.toLowerCase().endsWith(requiredDomain)) {
            return res.status(400).json({ 
                message: `El registro solo está permitido para correos que terminan en ${requiredDomain}.` 
            });
        }
        
        // 3. CONTINUAR CON EL PROCESO NORMAL
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const result = await db.query(
            `INSERT INTO users (full_name, email, password_hash, phone, role, student_id)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id, full_name, email, role, student_id`,
            [full_name, email, hashedPassword, phone, role || 'client', student_id]
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
// RUTA DE LOGIN (ASUME LÓGICA EXISTENTE)
// ==========================================================

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    // (Aquí va la lógica que ya tenías para buscar el usuario y verificar la contraseña)
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
                // Agrega student_id si es necesario: student_id: user.student_id 
            }
        });

    } catch (error) {
        console.error("Error en el login:", error);
        res.status(500).json({ message: "Error interno del servidor." });
    }
});

// ==========================================================
// RUTA DE ÓRDENES (PROTEGIDA)
// ==========================================================

// app.post('/api/orders', verifyToken, async (req, res) => {
//     // Esta es la ruta que ya tenías funcionando
//     // Aquí el req.user contiene el ID y el rol del usuario logueado
//     // (Debes insertar la lógica de creación de orden aquí)
    
//     // Respuesta de ejemplo que ya tenías funcionando
//     res.status(201).json({ message: "Orden creada exitosamente." });
// });

// ==========================================================
// INICIO DEL SERVIDOR
// ==========================================================

app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});
