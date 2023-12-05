const socks5 = require('socks5');
const ws = require('ws');
const http = require('http');
const fs = require('fs');
const YAML = require('yaml');
const net = require('net');
const { generateID } = require('./generators');
const { decrypt, encrypt } = require('./encryption');
const { getArgument } = require('./arguments');

const config = YAML.parse(fs.readFileSync('config.yml', 'utf-8'));

const url = getArgument('url', config.url);
const aesKey = getArgument('aes-key', config.aesKey);

const username = getArgument('username', config.username);
const password = getArgument('password', config.password);

const tunnels = config.tunnels;

var sock = new ws.WebSocket(url, {
    rejectUnauthorized: false
});

var sockets = {};
var incomingSockets = {};

sock.on('open', async () => {
    sock.send(YAML.stringify({
        _: 'Authorization',
        username,
        password,
        tunnels
    }));
});

sock.on('message', async (message, isBinary) => {
    message = message.toString('utf-8');
    const data = YAML.parse(message);
    for (const msg of data.data) {
        // if else if else if else if else if else if else if else if else if else if else
        if (msg.handler == 'Connection' && msg.type == 'Open') {
            sockets[msg.socketId].ready();
            sockets[msg.socketId].on('data', (buffer) => {
                sock.send(YAML.stringify({
                    _: 'Write',
                    socketId: msg.socketId,
                    data: encrypt(buffer, aesKey).toString('binary')
                }));
            });
        } else if (msg.handler == 'Connection' && msg.type == 'Closed') {
            sockets[msg.socketId].destroy();
            delete sockets[msg.socketId];
        } else if (msg.handler == 'Connection' && msg.type == 'Data') {
            sockets[msg.socketId].write(decrypt(msg.data, aesKey));
        }
        if (msg.handler == 'IncomingConnection') {
            if (msg.type == 'Open') {
                const tun = tunnels[msg.port];
                const conn = net.createConnection({
                    host: tun.host,
                    port: tun.port
                }, () => {
                    incomingSockets[msg.socketId] = conn;
                    conn.on('data', (buffer) => {
                        sock.send(YAML.stringify({
                            _: 'Write',
                            socketId: msg.socketId,
                            data: encrypt(buffer, aesKey).toString('binary')
                        }));
                    });
                });
                conn.ready = () => {};
                conn.on('close', () => {
                    sock.send(YAML.stringify({
                        _: 'CloseConnection',
                        socketId: msg.socketId
                    }));
                });
            } else if (msg.type == 'Data') {
                incomingSockets[msg.socketId].write(decrypt(msg.data, aesKey));
            } else if (msg.type == 'Closed') {
                incomingSockets[msg.socketId].destroy();
                delete incomingSockets[msg.socketId];
            }
        }
        if (msg.message)
            console.log(`[${new Date().toLocaleTimeString()}] [${msg.handler}] ${msg.type}: ${msg.message}`);
    }
});

if (config.socks.enabled) {
    const server = socks5.createServer(async (socket, port, address, proxy_ready) => {
        const id = generateID();
        sockets[id] = socket;
        socket.ready = () => {
            proxy_ready();
        };
        socket.on('close', () => {
            sock.send(YAML.stringify({
                _: 'CloseConnection',
                socketId: id
            }));
        });
        sock.send(YAML.stringify({
            _: 'CreateConnection',
            host: address,
            port,
            socketId: id
        }));
    });

    server.listen(config.socks.port, config.socks.host);
}

if (config.http.enabled) {
    const server = http.createServer();
    server.on('request', (req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end("SecureConnect HTTP proxy should be used for CONNECT requests. Try using HTTPS or use SOCKS5.");
    });

    server.on('connect', (req, socket, head) => {
        const [host, port] = req.url.split(':');
        const id = generateID();
        sockets[id] = socket;
        socket.ready = () => {
            socket.write(`HTTP/1.1 200 Connection Established\r\n\r\n`);
        };
        socket.on('close', () => {
            sock.send(YAML.stringify({
                _: 'CloseConnection',
                socketId: id
            }));
        });
        sock.send(YAML.stringify({
            _: 'CreateConnection',
            host,
            port,
            socketId: id
        }));
    });

    server.listen(config.http.port, config.http.host);
}

for (const gate of config.tcp) {
    net.createServer((socket) => {
        socket.pause();
        const id = generateID();
        sockets[id] = socket;
        socket.ready = () => {
            socket.resume();
        };
        socket.on('error', (err) => {

        });
        socket.on('close', () => {
            sock.send(YAML.stringify({
                _: 'CloseConnection',
                socketId: id
            }));
        });
        sock.send(YAML.stringify({
            _: 'CreateConnection',
            host: gate.targetHost,
            port: gate.targetPort,
            socketId: id
        }));
    }).listen(gate.port, gate.host);
}