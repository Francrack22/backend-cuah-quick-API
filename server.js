const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');

const app = express();
app.use(cors()); 
app.use(express.json());

// === USANDO VARIABLES DE ENTORNO PARA SEGURIDAD ===
const db = mysql.createConnection({
    host: process.env.DB_HOST,             // Ya no va la dirección real aquí
    user: process.env.DB_USER,             // Ya no va 'doadmin' aquí
    password: process.env.DB_PASSWORD,     // ¡Ya no va tu contraseña real aquí!
    database: process.env.DB_NAME,         // Usaremos una variable también
    port: 25060,
    ssl: { rejectUnauthorized: false }    
});

// Prueba de conexión a DigitalOcean
db.connect(err => {
    if (err) {
        console.error('❌ Error conectando a la base de datos:', err);
        return;
    }
    console.log('✅ Conectado a DigitalOcean');
});

// Ruta para que la página pida los productos
app.get('/api/products', (req, res) => {
    const sql = 'SELECT * FROM products WHERE is_available = 1';
    db.query(sql, (err, results) => {
        if (err) return res.status(500).send(err);
        res.json(results);
    });
});

// Arrancar el Servidor (usa el puerto de la nube o 3000 local)
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Servidor listo en puerto ${PORT}`);
});
