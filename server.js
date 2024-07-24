const jsonServer = require("json-server");
const jwt = require("jsonwebtoken");
const server = jsonServer.create();
const router = jsonServer.router("db.json");
const middlewares = jsonServer.defaults();
const port = process.env.PORT || 8080;
const cors = require('cors');
const bodyParser = require("body-parser");

server.use(cors());
server.use(middlewares);
server.use(bodyParser.json());

const SECRET_KEY = '123456789';
const expiresIn = '1h';

function createToken(payload) {
    return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

function verifyToken(token) {
    try {
        return jwt.verify(token, SECRET_KEY);
    } catch (err) {
        return null;
    }
}

function isAuthenticated({ email, password }) {
    const userdb = router.db.get('users').value();
    return userdb.findIndex(user => user.email === email && user.password === password) !== -1;
}

server.post('/auth/login', (req, res) => {
    const { email, password } = req.body;
    if (!isAuthenticated({ email, password })) {
        const status = 401;
        const message = 'Incorrect email or password';
        res.status(status).json({ status, message });
        return;
    }
    const access_token = createToken({ email, password });
    res.status(200).json({ access_token });
});

server.post('/auth/register', (req, res) => {
    const { email, password } = req.body;
    const userdb = router.db.get('users').value();
    if (userdb.findIndex(user => user.email === email) !== -1) {
        const status = 401;
        const message = 'Email already exists';
        res.status(status).json({ status, message });
        return;
    }
    router.db.get('users').push({ email, password }).write();
    const access_token = createToken({ email, password });
    res.status(200).json({ access_token });
});

// Public routes
server.use('/products', (req, res, next) => {
    next();
});

// Authentication middleware
server.use(/^(?!\/auth).*$/, (req, res, next) => {
    if (req.headers.authorization === undefined || req.headers.authorization.split(' ')[0] !== 'Bearer') {
        const status = 401;
        const message = 'Bad authorization header';
        res.status(status).json({ status, message });
        return;
    }
    const token = req.headers.authorization.split(' ')[1];
    const verifyTokenResult = verifyToken(token);

    if (!verifyTokenResult) {
        const status = 401;
        const message = 'Error: access_token is not valid';
        res.status(status).json({ status, message });
        return;
    }
    next();
});

server.use(router);

server.listen(port, () => {
    console.log(`Json server running on port ${port}`);
});
