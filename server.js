// server.js - Backend Cuah-Quick API (Final con MySQL y Roles)

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

// Conexión a la Base de Datos MySQL
// Utiliza la variable de entorno DATABASE_URL (que debe ser mysql://...)
const dbUrl = process.env.DATABASE_URL;
if (!dbUrl) {
    console.error("❌ ERROR: La variable DATABASE_URL no está configurada. El servidor no puede iniciar la conexión.");
    // Detiene el despliegue si la variable crítica no existe.
    throw new Error("La variable DATABASE_URL es requerida para la conexión a la base de datos.");
}
const pool = mysql.createPool(dbUrl);


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
        const { full_name, email, password, phone, student_id } = req.body;
        
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
        const finalRole = 'client'; // El rol por defecto es 'client'
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
// RUTA DE CREACIÓN DE ÓRDENES DEL CLIENTE (POST /api/orders)
// ==========================================================

app.post('/api/orders', verifyToken, async (req, res) => {
    // El ID del usuario está en el token, gracias a verifyToken
    const user_id = req.user.id; 
    
    // Obtenemos la información del pedido del cuerpo de la solicitud
    const { shop_id, total_amount, building, classroom, delivery_notes } = req.body;
    
    // Validaciones mínimas
    if (!shop_id || !total_amount || !building || !classroom) {
        return res.status(400).json({ message: "Faltan campos obligatorios para el pedido." });
    }

    try {
        const status = 'pending';
        
        // Ejecución de la consulta SQL con MySQL2
        const [result] = await pool.execute(
            `INSERT INTO orders (user_id, shop_id, total_amount, building, classroom, delivery_notes, status)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [user_id, shop_id, total_amount, building, classroom, delivery_notes || '', status]
        );

        res.status(201).json({ 
            message: "Orden creada exitosamente.",
            order_id: result.insertId
        });

    } catch (error) {
        console.error("Error al crear la orden:", error);
        res.status(500).json({ message: "Error interno del servidor al procesar la orden." });
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
                u.phone AS client_phone,
                o.building,
                o.classroom,
                o.delivery_notes
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
// INICIO DEL SERVIDOR
// ==========================================================

app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});
