const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
dotenv.config();
mongoose.connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('✅ MongoDB Connected');
  })
  .catch((err) => {
    console.error('❌ MongoDB Connection Error:', err.message);
  });
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
app.use('/api/user', require('./routes/auth'));
app.use('/api/organization', require('./routes/organization'));
app.use('/api/idor', require('./routes/idor'));
app.use('/api/hash', require('./routes/hash'));
app.use('/api/scan', require('./routes/scan'));
app.use('/api/network', require('./routes/network'));
app.use('/api/apivuln', require('./routes/apivuln'));
app.use('/api/apirecon', require('./routes/apirecon'));
app.use('/api/fixguide', require('./routes/fixguide'));
app.use('/api/report', require('./routes/report'));
app.use('/api/project', require('./routes/project'));
app.use('/api/asset', require('./routes/asset'));
app.use('/api/finding', require('./routes/finding'));
app.use('/api/httprequest', require('./routes/httprequest'));
app.use('/api/scanjob', require('./routes/scanjob'));
app.use('/api/takeover', require('./routes/takeover'));

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
