// server.js - Backend Cuah-Quick API (CORREGIDO PARA MYSQL)

const express = require('express');
const mysql = require('mysql2/promise'); // Usamos mysql2/promise para async/await
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// ==========================================================
// CONFIGURACIÓN DE MIDDLEWARES Y BASE DE DATOS (MySQL)
// ==========================================================

app.use(cors());
app.use(express.json());

// Conexión a la Base de Datos MySQL (usando variables de DigitalOcean)
// Nota: Usamos mysql.createPool para manejar múltiples conexiones
const pool = mysql.createPool(process.env.DATABASE_URL);


// Middleware de verificación de Token JWT (para rutas protegidas)
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
        req.user = user; 
        next();
    });
};

// Middleware 2: Verifica que el usuario sea 'shop'
const isShop = (req, res, next) => {
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
        const finalRole = 'client'; 
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Ejecución de la consulta SQL con MySQL2
        const [result] = await pool.execute(
            `INSERT INTO users (full_name, email, password_hash, phone, role, student_id)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [full_name, email, hashedPassword, phone, finalRole, student_id]
        );

        // En MySQL2, el ID insertado está en result.insertId
        const newUser = { 
            id: result.insertId, 
            full_name, email, 
            role: finalRole, 
            student_id 
        };
        
        const token = jwt.sign(
            { id: newUser.id, role: newUser.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(201).json({ 
            message: "Registro exitoso.", 
            token,
            user: newUser
        });

    } catch (error) {
        // El código 'ER_DUP_ENTRY' es el equivalente a '23505' de PostgreSQL
        if (error.code === 'ER_DUP_ENTRY') { 
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
        // Ejecución de la consulta SQL con MySQL2
        const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
        const user = rows[0]; // MySQL devuelve el resultado en la primera posición del array

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
app.get('/api/shop/orders', verifyToken, isShop, async (req, res) => {
    try {
        // Consulta SQL con sintaxis MySQL
        const [orders] = await pool.execute(`
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
            orders: orders
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
    res.status(201).json({ message: "Ruta de creación de orden (pendiente de implementación)." });
});

// ==========================================================
// INICIO DEL SERVIDOR
// ==========================================================

app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});
