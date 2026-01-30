import crypto from "crypto";

const data = "432decb9-26cc-42e8-b2cc-8825d6c14ccb_1762239628958_J9pBfAXCSzkS";
const signatureBase64 = "ZTFjMTQxNDk4MDU3ZGU5ODA1NzUwMzg0ZWQxYjFiMTdiZTMyNj..."; // 截断
const firmwarePubKeyPem = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnfXI7h+cQ6e80HUXAKS19pjb3KyP
ctBNoqNyoVtN2THgBPeCN+QgQ8KvEFWTPxbLidIwUwfxWlZ8b9lEeEWO7g==
-----END PUBLIC KEY-----`;

// 直接把 Base64 签名转 Buffer
const sigBuf = Buffer.from(signatureBase64, "base64");

// data buffer
const dataBuf = Buffer.from(data, "utf-8");

// 验证签名
const verify = crypto.createVerify("sha256");
verify.update(dataBuf);
verify.end();

const verified = verify.verify(firmwarePubKeyPem, sigBuf);
console.log("🔐 cryptoVerify result:", verified);
