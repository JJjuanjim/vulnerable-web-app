// Pruebas interactivas de las vulnerabilidades

async function testSQLi() {
    const user = document.getElementById('sqli-user').value;
    const pass = document.getElementById('sqli-pass').value;
    const resElem = document.getElementById('sqli-result');

    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: user, password: pass })
        });
        const data = await response.json();
        resElem.innerText = JSON.stringify(data, null, 2);
    } catch (e) {
        resElem.innerText = "Error: " + e.message;
    }
}

async function testCmd() {
    const host = document.getElementById('cmd-host').value;
    const resElem = document.getElementById('cmd-result');

    try {
        const response = await fetch('/api/ping?host=' + encodeURIComponent(host));
        const data = await response.json();
        resElem.innerText = JSON.stringify(data, null, 2);
    } catch (e) {
        resElem.innerText = "Error: " + e.message;
    }
}

function testXSS() {
    const payload = document.getElementById('xss-input').value;
    const resElem = document.getElementById('xss-result');
    resElem.innerHTML = "Abriendo ventana con payload XSS reflejado...";
    window.open('/api/search?q=' + encodeURIComponent(payload), '_blank');
}

async function testPath() {
    const file = document.getElementById('path-file').value;
    const resElem = document.getElementById('path-result');

    try {
        const response = await fetch('/api/view-file?file=' + encodeURIComponent(file));
        const data = await response.text();
        resElem.innerText = data;
    } catch (e) {
        resElem.innerText = "Error: " + e.message;
    }
}

async function testCrypto() {
    const pass = document.getElementById('crypto-pass').value;
    const resElem = document.getElementById('crypto-result');

    try {
        const response = await fetch('/api/hash-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: pass })
        });
        const data = await response.json();
        resElem.innerText = JSON.stringify(data, null, 2);
    } catch (e) {
        resElem.innerText = "Error: " + e.message;
    }
}

async function testSSRF() {
    const url = document.getElementById('ssrf-url').value;
    const resElem = document.getElementById('ssrf-result');

    try {
        const response = await fetch('/api/fetch-remote?url=' + encodeURIComponent(url));
        const data = await response.json();
        resElem.innerText = JSON.stringify(data, null, 2);
    } catch (e) {
        resElem.innerText = "Error: " + e.message;
    }
}

function testRedirect() {
    const target = document.getElementById('redirect-url').value;
    window.open('/api/redirect?url=' + encodeURIComponent(target), '_blank');
}

async function testBugs() {
    const resElem = document.getElementById('bugs-result');
    try {
        const response = await fetch('/api/test-bugs');
        const data = await response.json();
        resElem.innerText = JSON.stringify(data, null, 2);
    } catch (e) {
        resElem.innerText = "Error: " + e.message;
    }
}
