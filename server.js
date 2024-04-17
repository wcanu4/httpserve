const express = require('express');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors({ origin: 'http://localhost:4200' }));
// Almacenamiento en memoria para los datos
const storage = {
  credentials: {}, // Almacena las credenciales (key y shared_secret)
  messages: {} // Almacena los mensajes
};


// Middleware de autenticación opcional
function authenticate(req, res, next) {
  const { headers, body, params } = req;
  const { 'x-key': key, 'x-route': route, 'x-signature': signature } = headers;

  // Verificar que todos los encabezados necesarios estén presentes
  if (!key || !route || !signature) {
    return res.status(403).send('Faltan encabezados de autenticación');
  }

  // Obtener los datos que se van a firmar
  let dataToSign = '';
  if (body) {
    dataToSign += Object.entries(body).map(([key, value]) => `${key}:${value}`).join(';');
  }
  if (params) {
    dataToSign += Object.entries(params).map(([key, value]) => `${key}:${value}`).join(';');
  }
  dataToSign += `x-route:${route}`;

  // Calcular la firma HMAC-SHA256
  const hmac = crypto.createHmac('sha256', storage.credentials[key].shared_secret);
  hmac.update(dataToSign);
  const calculatedSignature = hmac.digest('hex');

  // Verificar que la firma coincida con la esperada
  if (calculatedSignature !== signature) {
    return res.status(403).send('Firma inválida');
  }

  next();
}

// Ruta no autenticada para almacenar credenciales
app.put('/credential', (req, res) => {
  const { key, shared_secret } = req.body;

  if (storage.credentials[key]) {
    return res.status(403).send('La clave ya existe');
  }

  storage.credentials[key] = { shared_secret };
  res.status(204).send();
});

// Ruta para obtener las credenciales almacenadas
app.get('/credentials', (req, res) => {
  res.status(200).json(storage.credentials);
});


// Rutas autenticadas (opcional)
app.post('/message', (req, res) => {
  const { msg, tags } = req.body;
  const messageId = generateUniqueId();
  storage.messages[messageId] = { msg, tags };
  res.status(200).json({ messageId });
});

app.get('/message/:id', (req, res) => {
  const { id } = req.params;
  const message = storage.messages[id];
  if (!message) {
    return res.status(404).send('Mensaje no encontrado');
  }
  res.status(200).json(message);
});

app.get('/messages/:tag', (req, res) => {
  const { tag } = req.params;
  const messagesWithTag = Object.values(storage.messages).filter(message => message.tags.includes(tag));
  res.status(200).json(messagesWithTag);
});

// Ruta para eliminar un mensaje
app.delete('/message/:id', (req, res) => {
  const { id } = req.params;
  
  // Verificar si el mensaje existe
  if (!storage.messages[id]) {
    return res.status(404).send('Mensaje no encontrado');
  }

  // Eliminar el mensaje del almacenamiento
  delete storage.messages[id];

  // Respuesta exitosa
  res.status(204).send();
});


// Función para generar un identificador único
function generateUniqueId() {
  return Math.random().toString(36).substr(2, 9);
}

// Puerto en el que escucha el servidor
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Servidor ejecutándose en el puerto ${PORT}`);
});
