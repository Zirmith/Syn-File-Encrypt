const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const config = require('./config');
const fileRouter = require('./routes');

const app = express();

// Parse incoming request bodies in a middleware before your handlers
app.use(bodyParser.json());


// Enable cross-origin requests if allowed in config
if (config.main.allowCrossOrigin) {
  app.use(cors());
}

// Set up routes
app.use('/syn/api/v1', fileRouter);

// Start the server listening on the configured port
app.listen(config.main.port, () => {
  console.log(`Server listening on port ${config.main.port}`);
});
