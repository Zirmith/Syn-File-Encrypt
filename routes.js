const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const config = require('./config');


// Set up Multer middleware for file uploads
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, './uploads/');
    },
    filename: (req, file, cb) => {
      cb(null, `${Date.now()}-${file.originalname}`);
    }
  })
});

// Define user authentication middleware
const authenticateUser = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authentication failed: missing token' });
  }
  const token = authHeader.split(' ')[1];

  jwt.verify(token, config.main.jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Authentication failed: invalid token' });
    }

    req.user = decoded;
    next();
  });
};



 // Define endpoint for file encryption
router.post('/encrypt', authenticateUser, upload.single('file'), (req, res) => {
  const { algorithm, key } = req.body;
  const inputFile = path.resolve(req.file.path);
  const outputFile = path.resolve(`${req.file.path}.enc`);
  const cipher = crypto.createCipher(algorithm, key);

  const input = fs.createReadStream(inputFile);
  const output = fs.createWriteStream(outputFile);

  input.pipe(cipher).pipe(output);

  output.on('finish', () => {
    const userDir = path.resolve(`./users/${req.user.id}`);
    if (!fs.existsSync(userDir)) {
      fs.mkdirSync(userDir);
    }
    const newFilePath = path.resolve(`${userDir}/${req.file.originalname}.enc`);
    fs.renameSync(outputFile, newFilePath);
    res.status(201).json({ message: 'File encrypted and stored successfully' });
  });
});


// Define endpoint for file decryption
router.post('/decrypt', authenticateUser, upload.single('file'), (req, res) => {
  const { algorithm, key } = req.body;
  const inputFile = path.resolve(req.file.path);
  const outputFile = path.resolve(`${req.file.path}.dec`);
  const decipher = crypto.createDecipher(algorithm, key);

  const input = fs.createReadStream(inputFile);
  const output = fs.createWriteStream(outputFile);

  input.pipe(decipher).pipe(output);

  output.on('finish', () => {
    const userDir = path.resolve(`./users/${req.user.id}`);
    if (!fs.existsSync(userDir)) {
      fs.mkdirSync(userDir);
    }
    const newFilePath = path.resolve(`${userDir}/${req.file.originalname}.dec`);
    fs.renameSync(outputFile, newFilePath);
    res.status(201).json({ message: 'File decrypted and stored successfully' });
  });
});


router.get('/files/:userId/:filename', (req, res) => {
    const { userId, filename } = req.params;
    const userDir = path.resolve(`./users/${userId}`);
    const filePath = path.resolve(`${userDir}/${filename}`);
  
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ message: 'File not found' });
    }
  
    const file = fs.createReadStream(filePath);
    res.setHeader('Content-Type', 'application/octet-stream');
    file.pipe(res);
  });


  // Define endpoint for reporting dangerous files
router.post('/report', authenticateUser, (req, res) => {
    const { file } = req.body;
  
    if (!file) {
      return res.status(400).json({ message: 'Missing file information' });
    }
  
    // TODO: Add code to flag the file as dangerous in the database or log a report
    res.status(200).json({ message: 'File reported as dangerous' });
  });
  

  
  // Define endpoint for user registration
  router.post('/register', (req, res) => {
    const { username, password } = req.body;
  
    if (!username || !password) {
      return res.status(400).json({ message: 'Invalid request: missing username or password' });
    }
  
    if (config.main.users.some(user => user.username === username)) {
      return res.status(400).json({ message: 'Username already exists' });
    }
  
    const id = Date.now().toString();
    console.log(id)
    config.main.users.push({ id, username, password });
    res.status(201).json({ message: 'User created successfully', id });
  });
  
  // Define endpoint for user login
  router.post('/login', (req, res) => {
    const { username, password } = req.body;
  
    if (!username || !password) {
      return res.status(400).json({ message: 'Invalid request: missing username or password' });
    }
  
    const user =  config.main.users.find(user => user.username === username && user.password === password);
  
    if (!user) {
      return res.status(401).json({ message: 'Authentication failed: invalid credentials' });
    }
  
    const token = jwt.sign({ id: user.id }, config.main.jwtSecret, { expiresIn: '1h' });
    res.status(200).json({ message: 'Login successful', token });
  });
  

module.exports = router;
