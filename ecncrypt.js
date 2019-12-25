eval(postman.getGlobalVariable("forgeJS"));

function parseResponse() {
    let resp =  pm.response;
    let level = pm.environment.get("encrypt_level");
    let accept = pm.environment.get("encrypt_accept");
    if (!accept || accept.lenght == 0) {
        accept = level;
    }

    switch (accept) {
        case "L1":
            body = decryptL1(resp);
            break;
        case "L2":
            body = decryptL2(resp);
            break;
        default:
            body =  resp.json();
            break;
    }
    return body;
}

function sendRequest(body) {
    let nonce = pm.environment.get("nonce");
    let agent_id = pm.variables.get("agent_id");
    let agent_key = pm.variables.get("agent_key");

    let level = pm.environment.get("encrypt_level");

    switch (level) {
        case "L1":
            body = encryptL1(body);
            break;
        case "L2":
            body = encryptL2(body);
            break;
        default:
            break;
    }

    pm.environment.set("body_content", body);

    addRequestHeader('content-type', pm.environment.get("content_type"));
    addRequestHeader('x-lehui-agentid', pm.environment.get("agent_id"));
    addRequestHeader('x-lehui-nonce', pm.environment.get("nonce"));
    addRequestHeader('x-lehui-encryption-level', pm.environment.get("encrypt_level"));
    addRequestHeader('x-lehui-encryption-accept', pm.environment.get("encrypt_accept"));

    let signature = sign(agent_id, agent_key, nonce, body)
    addRequestHeader('x-lehui-signature', signature);
}


function encryptL1(body) {
    let secret_key = randomWord(false, 16); // forge.random.getBytesSync(16);
    pm.environment.set("aes_secret_key", secret_key);

    let encryptedKey = rsa_encrypt( pm.environment.get("server_public_key"), secret_key)

    addRequestHeader('x-lehui-encryption-key', encryptedKey);

    let encryptedKeySign = rsa_sign(pm.environment.get("client_private_key"), forge.util.decode64(encryptedKey));

    addRequestHeader('x-lehui-encryption-sign', encryptedKeySign);

    return aes_encrypt(secret_key, body);
}

function decryptL1(response) {
    let encryptedKey = pm.response.headers.get("x-lehui-encryption-key")

    let clientPriKey = pm.environment.get("client_private_key")
    let secretKey = rsa_decrypt(clientPriKey, encryptedKey)

    let serverPubKey = pm.environment.get("server_public_key");
    let secretKeySign = pm.response.headers.get("x-lehui-encryption-sign")

    // let verified = rsa_verify(serverPubKey, forge.util.decode64(encryptedKey), secretKeySign)

    let decrypted = aes_decrypt(secretKey, pm.response.text())

    return JSON.parse(decrypted);
}

function encryptL2(body) {
    // TODO
}

function decryptL2(body) {
    // TODO
}

function sign(agent_id,agent_key, nonce, body) {
    let digest = "agent_id=" + agent_id + "&body=" + body + "&nonce=" + nonce;
    let buf = CryptoJS.HmacSHA256(digest, agent_key);
    return CryptoJS.enc.Hex.stringify(buf);
}

function addRequestHeader(k, v) {
    pm.request.headers.add({
        key: k,
        value: v
    });
}

function rsa_encrypt(pubKey, data) {
    let publicKey = forge.pki.publicKeyFromPem(pubKey);

    let encrypted = publicKey.encrypt(data, 'RSAES-PKCS1-V1_5')

    return forge.util.encode64(encrypted);
}

function rsa_decrypt(priKey, data) {
    let private_key = forge.pki.privateKeyFromPem(priKey);

    return private_key.decrypt(forge.util.decode64(data), 'RSAES-PKCS1-V1_5')
}

function rsa_sign(priKey, data) {
    let private_key = forge.pki.privateKeyFromPem(priKey);

    let md = forge.md.sha256.create();
    md.update(data);
    return forge.util.encode64(private_key.sign(md));
}

function rsa_verify(pubKey, data, sign) {
    let public_key = forge.pki.publicKeyFromPem(pubKey);

    let md = forge.md.sha256.create();
    md.update(data);
    return public_key.verify(md.digest().bytes(), forge.util.decode64(sign));
}


function aes_encrypt(key, body) {
    let iv = forge.random.getBytesSync(16);

    let cipher = forge.cipher.createCipher('AES-CBC', key);

    cipher.start({iv: iv});
    cipher.update(forge.util.createBuffer(body));
    cipher.finish();
    let ciphertext = cipher.output.bytes()

    let buffer = forge.util.createBuffer(iv);
    buffer.putBytes(ciphertext)

    return forge.util.encode64(buffer.getBytes());
}

function aes_decrypt(key, body) {
    body = forge.util.decode64(body);

    let iv =  body.slice(0, 16);
    let ciphertext = body.slice(16);

    var decipher = forge.cipher.createDecipher('AES-CBC', key);
    decipher.start({iv: iv});
    decipher.update(forge.util.createBuffer(ciphertext));
    var result = decipher.finish();

    return forge.util.decodeUtf8(decipher.output.getBytes());
}


function randomWord(randomFlag, min, max){
    var str = "",
        range = min,
        arr = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'];

    // 随机产生
    if(randomFlag){
        range = Math.round(Math.random() * (max-min)) + min;
    }
    for(var i=0; i<range; i++){
        pos = Math.round(Math.random() * (arr.length-1));
        str += arr[pos];
    }
    return str;
}
