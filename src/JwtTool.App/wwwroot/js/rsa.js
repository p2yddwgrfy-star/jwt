// RS256 signature verification via the browser's Web Crypto (crypto.subtle).
// .NET's RSA implementation is unavailable on browser WebAssembly, so the Blazor app
// delegates the RSA operation here. The key material never leaves the browser.
window.jwtRsa = {
    verify: async (signingInput, signature, pem) => {
        const der = pemToDer(pem);
        const algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
        let key;
        try {
            key = await crypto.subtle.importKey('spki', der, algorithm, false, ['verify']);
        } catch {
            key = await crypto.subtle.importKey('pkcs8', der, algorithm, false, ['verify']);
        }
        return await crypto.subtle.verify(algorithm, key, signature, new TextEncoder().encode(signingInput));
    },
    sign: async (signingInput, pem) => {
        const der = pemToDer(pem);
        const algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
        const key = await crypto.subtle.importKey('pkcs8', der, algorithm, false, ['sign']);
        const signature = await crypto.subtle.sign(algorithm, key, new TextEncoder().encode(signingInput));
        // .NET's InvokeAsync<byte[]> deserializes a base64 string (System.Text.Json's
        // byte[] format) — a plain JS array of numbers does not convert.
        return arrayBufferToBase64(signature);
    }
};

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
}

function pemToDer(pem) {
    const base64 = pem.replace(/-----(BEGIN|END)[^-]*-----/g, '').replace(/\s+/g, '');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}
