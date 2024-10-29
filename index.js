import http from 'http';
import pkg from 'http-proxy';
const { createProxyServer } = pkg;
import fetch from 'node-fetch';
import https from 'https';
import url from 'url';

const proxy = createProxyServer({ ws: true, secure: false, timeout: 0 }); // Set timeout to 0 for no timeout

const agent = new https.Agent({
    rejectUnauthorized: false
});

proxy.on('error', (err, req, res) => {
    console.error('Proxy error:', err);
});

const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Proxy server is active');
});

server.on('upgrade', async (req, socket, head) => {
    const parsedUrl = url.parse(req.url, true);
    const { vmId, csrfToken, ticket, nodeUrl, nodeName, vncPort } = parsedUrl.query;

    if (!vmId || !csrfToken || !ticket || !nodeUrl || !nodeName || !vncPort) {
        console.error('Missing required parameters');
        socket.destroy();
        return;
    }

    try {
        let originalHeaders = req.headers;
        req.headers = {
            'CSRFPreventionToken': csrfToken,
            'Cookie': `PVEAuthCookie=${ticket}`,
            'Content-Type': 'application/json',
        };

        const response = await fetch(`${nodeUrl}/nodes/${nodeName}/qemu/${vmId}/vncproxy`, {
            headers: req.headers,
            agent: agent,
            method: 'POST',
            body: JSON.stringify({ websocket: 1, 'generate-password': 1 }),
        });

        const data = await response.json();
        if (response.ok) {
            const ticket = data.data.ticket;
            let encodedTicket = encodeURIComponent(ticket);
            encodedTicket = encodedTicket.trim()
            const targetUrl = `${nodeUrl.replace('https', 'wss')}/nodes/${nodeName}/qemu/${vmId}/vncwebsocket?port=5977&vncticket=${encodedTicket}`;

            console.log('Upgrading to:', targetUrl);
                
            req.headers = {
                'Cookie': `PVEAuthCookie=${ticket}`,
                'connection': 'upgrade',
                'upgrade': 'websocket',
                'sec-websocket-key': originalHeaders['sec-websocket-key'],
                'sec-websocket-version': originalHeaders['sec-websocket-version'],
                'sec-websocket-extensions': 'permessage-deflate; client_max_window_bits',
                'sec-websocket-protocol': 'binary',
                'host': `${nodeUrl.replace('https://', '').replace('/api2/json', '')}`,
            };

            proxy.ws(req, socket, head, { target: targetUrl, secure: true });
        } else {
            throw new Error(`Failed to fetch ticket: ${data.message}`);
        }
    } catch (error) {
        console.error('Upgrade error:', error);
        socket.destroy();
    }
});

server.listen(3001, () => {
    console.log('Proxy server is running on ws://localhost:3001');
});
