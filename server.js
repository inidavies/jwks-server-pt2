const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();
let db = new sqlite3.Database('./totally_not_my_privateKeys.db')
db.run('DROP TABLE IF EXISTS keys')
db.run('CREATE TABLE IF NOT EXISTS keys( kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL, exp INTEGER NOT NULL)')

const app = express();
const port = 8080;

let keyPair;
let expiredKeyPair;
let token;
let expiredToken;

async function generateKeyPairs() {
  keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
}

function generateToken() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: keyPair.kid
    }
  };

  //store key in db
  //console.log(keyPair);
  var pem = keyPair.toPEM(true)
  db.run('INSERT INTO keys(key, exp) VALUES(?,?)',[pem, payload.exp], error => {
    if (error) throw error;
    console.log('Valid key stored in db')
  })

  //retrive valid key from db
  let now = Math.floor(Date.now() / 1000)
  db.all('SELECT key FROM keys WHERE exp > ?', [now], (error, row) => {
    if(error) throw error;
    token = jwt.sign(payload, row[0].key, options);
  })
}

function generateExpiredJWT() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000) - 30000,
    exp: Math.floor(Date.now() / 1000) - 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: expiredKeyPair.kid
    }
  };

  //store key in db
  db.run('INSERT INTO keys(key, exp) VALUES(?,?)',[expiredKeyPair.toPEM(true), payload.exp], error => {
    if (error) throw error;
    console.log('Expired key stored in db')
  })

  //retrieve expired key from db
  let now = Math.floor(Date.now() / 1000)
  db.all('SELECT key FROM keys WHERE exp <= ?', [now], (error, row) => {
    if(error) throw error;
    expiredToken = jwt.sign(payload, row[0].key, options);
  })
}

app.all('/auth', (req, res, next) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

// Middleware to ensure only GET requests are allowed for /jwks
app.all('/.well-known/jwks.json', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

app.get('/.well-known/jwks.json', (req, res) => {
  let now = Math.floor(Date.now() / 1000)
  db.all('SELECT * FROM keys WHERE exp > ?', [now], (error, row) => {
    if(error) throw error;
    if (row[0].key === keyPair.toPEM(true)){
      const validKeys = [keyPair].filter(key => !key.expired);
      res.setHeader('Content-Type', 'application/json');
      res.json({ keys: validKeys.map(key => key) });
    }
  })
});

app.post('/auth', (req, res) => {

  if (req.query.expired === 'true'){
    return res.send(expiredToken);
  }
  res.send(token);
});

generateKeyPairs().then(() => {
  generateToken()
  generateExpiredJWT()
  app.listen(port, () => {
    
    console.log(`Server started on http://localhost:${port}`);
  });
});

module.exports = app;
