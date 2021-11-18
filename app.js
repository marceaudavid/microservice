const express = require('express');
const axios = require('axios');
const bodyparser = require('body-parser');
const crypto = require('crypto');

const app = express();
app.use(bodyparser.json());
const port = 3000;

let keys;

// Fonction lancée eu démarrage du service
const start = async () => {
  // Envoie d'une requete
  let response;
  try {
    response = await axios.post(
      'http://10.44.17.33:1338/register',
      { host: 'http://10.44.16.131:3000', code: 'marceau.david' },
      {
        auth: {
          username: 'ynovset',
          password: 'tHuds4752_525@',
        },
      }
    );
  } catch (e) {
    console.error(e.response ? e.response.data : e);
    return;
  }
  keys = response.data;
  try {
    response = await axios.get('http://10.44.17.33:1338/registry', {
      headers: {
        'X-Auth-Token': keys.token,
      },
    });
  } catch (e) {
    console.error(e.response ? e.response.data : e);
    return;
  }
  await loop(response.data);
};

const unlock = async (host, code) => {
  let response, key;
  try {
    response = await axios.get(`${host}/getkey`, {
      headers: { 'X-Auth-Token': keys.token },
    });
  } catch (e) {
    console.error(
      '\x1b[31m',
      `${code}: cannot get key ${e.response ? `(${e.response.status})` : ''}`
    );
    return `${code}: cannot get key`;
  }
  if (response && response.data && response.data.encrypted_public_key) {
    key = response.data.encrypted_public_key;
    try {
      response = await axios.post(
        'http://10.44.17.33:1338/key/unlock',
        { code, key },
        { headers: { 'X-Auth-Token': keys.token } }
      );
    } catch (e) {
      console.error('\x1b[31m', `${code}: cannot unlock key`);
      return `${code}: cannot get key`;
    }
    console.log('\x1b[32m', `${code}: ${host}`);
    return `${code}: ${host}`;
  }
};

const loop = async (registry) => {
  await Promise.all(
    registry.map(async ({ code, host }) => {
      await unlock(host, code);
    })
  );
};

app.get('/ping', (req, res) => {
  res.status(200).send('OK');
});

// Création d'un endpoint en GET
app.get('/getkey', async (req, res) => {
  // Récuperer les headers
  let token = req.headers['x-auth-token'];
  if (!token) {
    res.status(403).send('Authentification invalide');
    return;
  }
  let response;
  try {
    response = await axios.post(
      'http://10.44.17.33:1338/token/validate',
      { token },
      {
        headers: {
          'X-Auth-Token': keys.token,
        },
      }
    );
  } catch (error) {
    if (error.response.status === 500) {
      res.status(502).send('L’annuaire est indisponible, impossible de vérifier le jeton');
      return;
    }
    res.status(500).send('Erreur inattendue');
    return;
  }
  if (!response.data.valid) {
    res.status(403).send('Authentification invalide');
    return;
  }
  let encrypted_public_key = encrypt(keys.secret_key, keys.public_key);
  res.status(200).json({ encrypted_public_key });
});

app.post('/newservice', async (req, res) => {
  let { host, code } = req.body;
  await unlock(host, code);
});

// Lancement du service
app.listen(port, () => {
  console.log('\x1b[32m', `Service listening at http://localhost:${port}`);
  start();
});

/**
 * Fonction de chiffrement
 * @param secretKey
 * @param publicKey
 * @returns {string}
 */
function encrypt(secretKey, publicKey) {
  return crypto.createHmac('sha256', secretKey).update(publicKey).digest('hex');
}
