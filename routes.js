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

    const user = config.main.users.find(user => user.id === decoded.id);
    if (!user) {
      return res.status(401).json({ message: 'Authentication failed: invalid token' });
    }

    

    console.log(`Token ${token}, is being used by a user with the following credentials: username=${user.username}`);

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
    const fileLink = `${req.protocol}://${req.get('host')}/syn/api/v1/files/${req.user.id}/${req.file.originalname}.enc`;
    res.status(201).json({ message: 'File encrypted and stored successfully', link: fileLink });
  });

  // Error catch
  output.on('error', (err) => {
    console.error(err);
    res.status(500).json({ message: 'Failed to encrypt file' });
  });
});


// Define endpoint for file decryption
router.post('/decrypt', authenticateUser, upload.single('file'), (req, res) => {
  const { algorithm, key } = req.body;
  const inputFile = path.resolve(req.file.path);
  const outputFile = path.resolve(`${req.file.path}.dec`);
  const iv = crypto.randomBytes(16);
  const decipher = crypto.createDecipheriv(algorithm, key, iv);

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
    const fileLink = `${req.protocol}://${req.get('host')}/syn/api/v1/files/${req.user.id}/${req.file.originalname}.dec`;
    res.status(201).json({ message: 'File decrypted and stored successfully', link: fileLink });
  });

  decipher.on('error', (error) => {
    console.error(`Error decrypting file: ${error}`);
    res.status(500).json({ message: 'Error decrypting file' });
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
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ message: 'Missing file URL' });
  }

  console.log(`Got Url: ${url}`);

  // Parse the URL to get the user ID and file name
  const regex = /files\/(\d+)\/(.+)/;
  const match = url.match(regex);

  if (!match) {
    return res.status(400).json({ message: 'Invalid file URL' });
  }

  const userId = match[1];
  console.log(`User Id Of Reported Url: ${userId}`)
  const filename = match[2];
  console.log(`File Name Of Reported Url: ${filename}`)
  // Check if the user ID is valid
  if (!config.main.users.some(user => user.id === userId)) {
    return res.status(400).json({ message: 'Invalid user ID' });
  }

  // Check if the file exists in the user's directory
  const userDir = path.resolve(`./users/${userId}`);
  const filePath = path.resolve(`${userDir}/${filename}`);

  if (!fs.existsSync(filePath)) {
    return res.status(400).json({ message: 'File not found' });
  }

  // Create a new directory for the dangerous files
  const newDirPath = path.resolve(`${userDir}/dangerous_files`);
  if (!fs.existsSync(newDirPath)) {
    fs.mkdirSync(newDirPath);
  }

  // Add code to flag the file as dangerous or add a warning to the README.md file
  const readmePath = path.resolve(`${userDir}/README.md`);
  const warningMsg = '\n\n**WARNING: This file may be dangerous or contain malicious code. Use with caution.**\n\n';

  console.log(`Writing Warning File to ${newDirPath}`)

  // Add a warning to the README.md file, if it exists
  if (fs.existsSync(readmePath)) {
    fs.appendFileSync(readmePath, warningMsg);
    console.log(`Warning has been Wrote`)
  } else {
    // Create a new README.md file with the warning message
    fs.writeFileSync(readmePath, warningMsg);
    console.log(`Warning has been Wrote`)
  }

  // Move the file to the new directory
  const newFilePath = path.resolve(`${newDirPath}/${filename}`);
  fs.renameSync(filePath, newFilePath);

  // Send a response with the link to the new file
  const fileLink = `http://syn-encrypt.onrender.com/syn/api/v1/files/${userId}/dangerous_files/${filename}`;
  console.warn(`Completed Warning / report of file ${fileLink}`)
  res.status(200).json({ message: 'File reported as dangerous', link: fileLink });
});





// Define endpoint for user registration
router.post('/register', (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Invalid request: missing username or password' });
    }

    if (config.main.users.some(user => user.username === username)) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    const id = Date.now().toString();
    const user = { id, username, password };
    config.main.users.push(user);

    res.status(201).json({ message: 'User created successfully', id });

   

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});


// Define endpoint for user login
router.post('/login', (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Invalid request: missing username or password' });
    }

    const user = config.main.users.find(user => user.username === username && user.password === password);

    if (!user) {
      return res.status(401).json({ message: 'Authentication failed: invalid credentials' });
    }

    const token = jwt.sign({ id: user.id }, config.main.jwtSecret, { expiresIn: '1h' });
    res.status(200).json({ message: 'Login successful', token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

module.exports = router;
