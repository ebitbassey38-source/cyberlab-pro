const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

app.use('/api/dirscan', require('./routes/dirscan'));
app.use('/api/sqli', require('./routes/sqli'));
app.use('/api/xss', require('./routes/xss'));
app.use('/api/auth', require('./routes/authtest'));
app.use('/api/idor', require('./routes/idor'));

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    app: 'CyberLab Pro',
    version: '1.0.0',
    timestamp: new Date().toISOString()
  });
});

app.listen(PORT, () => {
  console.log(`CyberLab Pro running on port ${PORT}`);
});
