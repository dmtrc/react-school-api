const fs = require('fs');
const bodyParser = require('body-parser');
const jsonServer = require('json-server');
const jwt = require('jsonwebtoken');

const DB_PATH = './db';
const PORT = 8080;

const server = jsonServer.create();
const router = jsonServer.router(`${DB_PATH}/posts.json`);
const userdb = JSON.parse(fs.readFileSync(`${DB_PATH}/users.json`, 'UTF-8'));

server.use(jsonServer.defaults());
server.use(bodyParser());

const SECRET_KEY = '123456789';
const expiresIn = 2000;
let accessToken = null;

// Create a token from a payload
function createToken(payload){
  return jwt.sign(payload, SECRET_KEY, {expiresIn})
}

// Verify the token
const verifyToken = token => {
  if ( token !== accessToken ) {
    throw new Error();
  }

  return true;
};

// Check if the user exists in database
function isAuthenticated({email, password}){
  return userdb.users.findIndex(user => user.email === email && user.password === password) !== -1
}

server.post('/auth/login', (req, res) => {
  const {email, password} = req.body;
  if (isAuthenticated({email, password}) === false) {
    const status = 401;
    const message = 'Incorrect email or password';
    res.status(status).json({status, message});
    return
  }
  const access_token = createToken({email, password});

  accessToken = access_token;

  // Emulate token expiration
  setTimeout(() => {
    accessToken = null;
  }, 3600000);

  res.status(200).json({access_token});
});

server.use(/^(?!\/auth).*$/,  (req, res, next) => {
  if (req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
    const status = 401;
    const message = 'Bad authorization header';
    res.status(status).json({status, message});
    return
  }
  try {
    verifyToken(req.headers.authorization.split(' ')[1]);
    next()
  } catch (err) {
    const status = 401;
    const message = 'Error: access_token is not valid';
    res.status(status).json({status, message})
  }
});

server.use((req, res, next) => {
  try {
    verifyToken(req.headers.authorization.split(' ')[1]);
    next()
  } catch (err) {
    const status = 401;
    const message = 'Error: access_token is not valid';
    res.status(status).json({status, message})
  }
});

server.use(router);

server.listen(PORT, () => {
  console.log(`Run Mock API Server on ${PORT}`);
});