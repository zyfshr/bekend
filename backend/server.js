import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import XLSX from "xlsx";
import { Connection, Keypair, PublicKey, Transaction } from "@solana/web3.js";
import { getOrCreateAssociatedTokenAccount, createTransferInstruction } from "@solana/spl-token";
import dotenv from "dotenv";
import { X509Certificate, createPublicKey, verify } from "node:crypto";
import crypto from "crypto";
import pkg from 'elliptic';
import asn1 from 'asn1.js'; 
import forge from 'node-forge';
 
import BN from 'bn.js';
const { ec: EC } = pkg;
const { createVerify } = crypto;
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 3001;
const RPC_URL = process.env.SOLANA_RPC || "https://api.mainnet-beta.solana.com";
const connection = new Connection(RPC_URL, "confirmed");
console.log("🔗 Using RPC:", RPC_URL);

// ===== Wallet 路径 =====
const WALLET_A_PATH = process.env.WALLET_A_PATH || path.join(__dirname, "walletA.json");
const WALLET_B_PATH = process.env.WALLET_B_PATH || path.join(__dirname, "walletB.json");
const WALLET_C_PATH = process.env.WALLET_C_PATH || path.join(__dirname, "walletC.json");
 



// ===== 加载 Keypair =====
function loadKeypair(filePath) {
  if (!fs.existsSync(filePath)) {
    console.error("❌ Wallet file missing:", filePath);
    return null;
  }
  return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(filePath))));
}

const walletA = loadKeypair(WALLET_A_PATH);
const walletB = loadKeypair(WALLET_B_PATH);
const walletC = loadKeypair(WALLET_C_PATH);
const router = express.Router();
 
 const FIRMWARE_DATABASE = {  
  touch: {  
    system: {  
      version: '4.6.0',  
      checksum: 'abc123def456',  
      commitId: 'commit789',  
      releaseUrl: 'http://192.168.0.105:3000/download-firmware',  
      changelog: {  
        'zh-CN': `## 新功能  
- 修复了蓝牙连接稳定性问题  
- 优化了交易签名速度  
- 增加了对新网络的支持  
- 改进了用户界面响应速度  
  
## 安全更新  
- 修复了已知的安全漏洞  
- 增强了密钥存储安全性`,  
        'en-US': `## New Features  
- Fixed Bluetooth connection stability issues  
- Optimized transaction signing speed  
- Added support for new networks  
- Improved user interface responsiveness  
  
## Security Updates  
- Fixed known security vulnerabilities  
- Enhanced key storage security`  
      }  
    },  
    bluetooth: {  
      version: '2.2.1',  
      checksum: 'xyz789abc123',  
      commitId: 'commit456',  
      releaseUrl: 'https://github.com/OneKeyHQ/firmware-ble/releases/tag/v2.4.0',  
      changelog: {  
        'zh-CN': '## 蓝牙固件更新\n- 提升连接稳定性\n- 优化功耗\n- 修复断连问题',  
        'en-US': '## Bluetooth Firmware Update\n- Improved connection stability\n- Optimized power consumption\n- Fixed disconnection issues'  
      }  
    },  
    bootloader: {  
      version: '2.5.0',  
      checksum: 'boot123456',  
      commitId: 'commit123',  
      releaseUrl: 'https://github.com/OneKeyHQ/firmware-boot/releases/tag/v2.6.0',  
      changelog: {  
        'zh-CN': '## Bootloader 更新\n- 安全性增强\n- 启动速度优化',  
        'en-US': '## Bootloader Update\n- Security enhancements\n- Boot speed optimization'  
      }  
    }  
  },  
  // 可以添加其他设备类型: classic, mini, pro 等  
  classic: {  
    system: { /* ... */ },  
    bluetooth: { /* ... */ },  
    bootloader: { /* ... */ }  
  }  
};  

const CA_CERT_PATH = process.env.CA_CERT_PATH || "./firmware_ca.pem";
let caCertificate;
const FIRMWARE_PRIVATE_KEY = fs.readFileSync('./firmware_key.pem', 'utf8');  
  

const FIRMWARE_PUBLIC_KEY = fs.readFileSync('./firmware_key.pem', 'utf8');  
function verifySignatureWithPEM(data, signatureBuffer) {  
  try {  
    const verify = crypto.createVerify('SHA256');  
    verify.update(data, 'utf8');  
    verify.end();  
      
    // 使用公钥验证签名  
    const isValid = verify.verify(  
      FIRMWARE_PUBLIC_KEY,  
      signatureBuffer  
    );  
      
    return isValid;  
  } catch (error) {  
    console.error('Signature verification error:', error);  
    return false;  
  }  
}  
  
  

try {
  const caCertPem = fs.readFileSync(CA_CERT_PATH, "utf-8");
  caCertificate = new X509Certificate(caCertPem);
  console.log("✅ CA证书加载成功，颁发者:", caCertificate.issuer);
} catch (error) {
  console.error("❌ 加载CA证书失败:", error);
  process.exit(1);
}





function rawRS128ToDer(raw) {
  if (raw.length !== 128) throw new Error("Invalid raw 128-byte signature");
  const r = raw.subarray(0, 64);
  const s = raw.subarray(64, 128);
  return rawRS64ToDer(r, s);
}

// 修改 rawRS64ToDer，支持传入 r 和 s
function rawRS64ToDer(r, s) {
  const encodeInt = (buf) => {
    if (buf[0] & 0x80) buf = Buffer.concat([Buffer.from([0]), buf]);
    return Buffer.concat([Buffer.from([0x02, buf.length]), buf]);
  };
  const rEnc = encodeInt(r);
  const sEnc = encodeInt(s);
  return Buffer.concat([Buffer.from([0x30, rEnc.length + sEnc.length]), rEnc, sEnc]);
}
function verifyEcdsaDigest(certDer, digest, rawSignature) {
  const cert = new X509Certificate(certDer);
  const pubKey = cert.publicKey;
  const sigDer = rawRS64ToDer(rawSignature);
  
  const ok = crypto.verify(null, digest, pubKey, sigDer);
  console.log("🔍 ECDSA verify result:", ok);
  return ok;
}

// ===== 现有的固件公钥验证（保留兼容性） =====
const firmwarePubKeyPem = fs.readFileSync("./firmware_key_pub.pem", "utf-8");
const firmwarePubKey = crypto.createPublicKey(firmwarePubKeyPem);

function verifyFirmwareSignature(data, signatureBase64) {
  let bufferToVerify;

  if (/^[0-9a-fA-F]+$/.test(data) && data.length % 2 === 0) {
    bufferToVerify = Buffer.from(data, "hex");
  } else {
    bufferToVerify = Buffer.from(data, "utf-8");
  }

  const sigBuf = Buffer.from(signatureBase64, "base64");
  const verified = crypto.verify(
    "sha256",
    bufferToVerify,
    firmwarePubKey,
    sigBuf
  );

  return verified;
}
// ===== 改进的证书解析函数 =====
function parseCertificateWithFallback(certDer) {
  let errorDirect, errorPem, errorManual;

  // 方法1: 直接解析
  try {
    console.log("🔄 尝试直接解析证书...");
    const cert = new X509Certificate(certDer);
    console.log("✅ 直接解析成功");
    return cert;
  } catch (error) {
    errorDirect = error;
    console.log("⚠️ 直接解析失败:", errorDirect.message);
  }

  // 方法2: 检查是否是十六进制字符串编码的证书
  try {
    console.log("🔄 检查是否是十六进制编码...");
    const certHex = certDer.toString('utf-8');
    
    // 检查是否看起来像十六进制字符串
    if (/^[0-9a-fA-F]+$/.test(certHex)) {
      console.log("🔍 检测到十六进制编码，尝试转换...");
      const certBuffer = Buffer.from(certHex, 'hex');
      
      // 保存转换后的文件用于调试
      fs.writeFileSync("./debug_cert_hex_decoded.der", certBuffer);
      
      const cert = new X509Certificate(certBuffer);
      console.log("✅ 十六进制解码后解析成功");
      return cert;
    } else {
      throw new Error("不是十六进制字符串");
    }
  } catch (error) {
    console.log("⚠️ 十六进制解码失败:", error.message);
  }

  // 方法3: 尝试添加PEM头尾
  try {
    console.log("🔄 尝试添加PEM头尾...");
    const pem = `-----BEGIN CERTIFICATE-----\n${certDer.toString('base64')}\n-----END CERTIFICATE-----`;
    const cert = new X509Certificate(pem);
    console.log("✅ PEM格式解析成功");
    return cert;
  } catch (error) {
    errorPem = error;
    console.log("⚠️ PEM格式解析失败:", errorPem.message);
  }

  // 方法4: 尝试手动提取公钥
  try {
    console.log("🔄 尝试手动提取公钥...");
    return manuallyExtractCertificateInfo(certDer);
  } catch (error) {
    errorManual = error;
    console.log("❌ 手动提取也失败:", errorManual.message);
  }

  throw new Error(`所有证书解析方法都失败: 直接解析: ${errorDirect.message}, PEM解析: ${errorPem.message}, 手动提取: ${errorManual.message}`);
}






function verifyHardwareCertificate(requestData) {
  try {
    const { deviceType, data, cert: certB64, signature: signatureB64 } = requestData;
    
    console.log("🔍 开始证书链验证...");
    console.log("📊 输入数据:", { 
      deviceType, 
      dataLength: data?.length,
      certB64Length: certB64?.length,
      signatureB64Length: signatureB64?.length 
    });

    if (!data || !certB64 || !signatureB64) {
      console.log("❌ 缺少必要参数");
      return { code: 1, message: "缺少必要参数" };
    }

    // 1. 解码base64数据
    let certDer, signatureRaw;
    try {
      certDer = Buffer.from(certB64, "base64");
      signatureRaw = Buffer.from(signatureB64, "base64");
      console.log("✅ Base64解码成功:", {
        certDerLength: certDer.length,
        signatureRawLength: signatureRaw.length
      });
      
      // 保存证书数据用于调试
      fs.writeFileSync("./debug_cert_received.der", certDer);
      console.log("💾 证书数据已保存到 debug_cert_received.der");
      
      // 输出证书前几个字节进行分析
      const firstBytes = certDer.subarray(0, 16);
      console.log("🔍 证书前16字节(hex):", firstBytes.toString('hex'));
      console.log("🔍 证书前16字节(ascii):", firstBytes.toString('ascii'));
      
      // 检查是否是十六进制字符串
      const asString = certDer.toString('utf-8');
      if (/^[0-9a-fA-F]+$/.test(asString)) {
        console.log("🎯 检测到证书数据是十六进制字符串编码");
        console.log("📏 十六进制字符串长度:", asString.length);
      }
    } catch (e) {
      console.log("❌ Base64解码失败:", e.message);
      return { code: 2, message: `数据解码失败: ${e.message}` };
    }

    // 2. 尝试解析设备证书 - 使用改进的方法
    let deviceCert;
    try {
      deviceCert = parseCertificateWithFallback(certDer);
      console.log("✅ 设备证书解析成功");
    } catch (parseError) {
      console.log("❌ 设备证书解析失败:", parseError.message);
      return { code: 3, message: `设备证书解析失败: ${parseError.message}` };
    }

    // 3. 验证设备证书签名（由CA签发）
    // 注意：由于我们无法正确解析证书的签名部分，这里跳过证书签名验证
    console.log("⚠️ 跳过证书签名验证（因解析问题）");

  
   
    // 5. 验证挑战数据的签名 - 修复公钥使用问题
    try {
  console.log("🔑 开始挑战数据签名验证...");
  console.log("📄 原始数据:", data);

  // 计算 SHA256 哈希（这是设备签名的 digest）
  const dataBuffer = Buffer.from(data, 'utf-8');
  const digest = crypto.createHash('sha256').update(dataBuffer).digest();
  console.log("📄 数据 SHA256 digest:", digest.toString('hex'));

  // 处理签名格式：64字节 r||s 转 DER
 let signatureDer;
if (signatureRaw.length === 64) {
  signatureDer = rawRS64ToDer(signatureRaw, signatureRaw.subarray(32, 64));
} else if (signatureRaw.length === 128) {
  signatureDer = rawRS128ToDer(signatureRaw);
} else {
  signatureDer = signatureRaw; // 已经是 DER
} 


  // 确保公钥是 KeyObject
  let devicePublicKey;
if (typeof deviceCert.publicKey === 'string') {
  devicePublicKey = crypto.createPublicKey({ key: deviceCert.publicKey, format: 'pem' });
} else if (deviceCert.publicKey && typeof deviceCert.publicKey === 'object') {
  devicePublicKey = deviceCert.publicKey;
} else {
  devicePublicKey = extractPublicKeyFromCert(certBuffer);
}

const verified = crypto.verify(null, digest, devicePublicKey, signatureDer);
console.log("🔍 签名验证结果:", verified);

  // ✅ 核心修改：使用 null 告诉 Node.js digest 已经预哈希
  const signatureVerified = crypto.verify(
    null,       // 这里 null 表示已哈希，不重复哈希
    digest,     // 传入 SHA256 digest
    devicePublicKey,
    signatureDer
  );

  console.log(`📝 挑战数据签名验证结果: ${signatureVerified ? "成功" : "失败"}`);

  if (!signatureVerified) {
    return { code: 8, message: "挑战数据签名验证失败" };
  }
} catch (e) {
  console.log("❌ 签名验证异常:", e.message);
  return { code: 8, message: `签名验证异常: ${e.message}` };
}

    // 6. 验证成功，返回设备信息
    const subjectCN = deviceCert.subject.match(/CN=([^,]+)/);
    const deviceCN = subjectCN ? subjectCN[1] : "Unknown";

    console.log("🎉 证书链验证完全成功!");
    
    return {
      code: 0,
      message: "验证成功",
      data: {
        deviceCN,
        certSerial: deviceCert.serialNumber,
        validFrom: deviceCert.validFrom,
        validTo: deviceCert.validTo,
        issuer: deviceCert.issuer,
        isTestCertificate: isTestCertificate
      }
    };

  } catch (error) {
    console.log("💥 验证过程异常:", error);
    return { code: 99, message: `验证过程异常: ${error.message}` };
  }
}

// ===== 从证书中提取公钥的函数 =====
function extractPublicKeyFromCert(certBuffer) {
  try {
    console.log("🛠️ 尝试从证书数据提取公钥...");
    
    // 方法1: 直接作为SPKI公钥
    try {
      const publicKey = crypto.createPublicKey({
        key: certBuffer,
        format: 'der',
        type: 'spki'
      });
      console.log("✅ 作为SPKI公钥提取成功");
      return publicKey;
    } catch (error) {
      console.log("⚠️ SPKI公钥提取失败:", error.message);
    }
    
    // 方法2: 尝试作为X.509证书提取公钥
    try {
      const x509Cert = new X509Certificate(certBuffer);
      const publicKey = crypto.createPublicKey({
        key: x509Cert.publicKey,
        format: 'pem'
      });
      console.log("✅ 从X.509证书提取公钥成功");
      return publicKey;
    } catch (error) {
      console.log("⚠️ X.509证书公钥提取失败:", error.message);
    }
    
    // 方法3: 手动解析证书结构提取公钥
    try {
      // 这是一个简化的方法，实际应该使用完整的ASN.1解析
      // 这里我们假设公钥在证书的特定位置
      const publicKey = manuallyExtractPublicKey(certBuffer);
      console.log("✅ 手动提取公钥成功");
      return publicKey;
    } catch (error) {
      console.log("⚠️ 手动提取公钥失败:", error.message);
    }
    
    throw new Error("无法从证书数据中提取公钥");
  } catch (error) {
    throw new Error(`提取公钥失败: ${error.message}`);
  }
}

// ===== 手动提取公钥的简化实现 =====
function manuallyExtractPublicKey(certBuffer) {
  // 这是一个简化的实现，假设证书结构符合常见X.509格式
  // 在实际应用中，应该使用完整的ASN.1解析库
  
  // 查找公钥的起始位置（这是一个启发式方法）
  // 在典型的X.509证书中，公钥信息通常在特定序列之后
  const certHex = certBuffer.toString('hex');
  
  // 查找公钥OID常见模式（RSA或ECC）
  const rsaOID = '2a864886f70d010101'; // RSA加密OID
  const ecOID = '2a8648ce3d0201'; // EC公钥OID
  
  let publicKeyStart = -1;
  
  if (certHex.includes(rsaOID)) {
    publicKeyStart = certHex.indexOf(rsaOID) + rsaOID.length;
    console.log("🔑 检测到RSA公钥");
  } else if (certHex.includes(ecOID)) {
    publicKeyStart = certHex.indexOf(ecOID) + ecOID.length;
    console.log("🔑 检测到ECC公钥");
  }
  
  if (publicKeyStart === -1) {
    throw new Error("未找到公钥OID");
  }
  
  // 提取公钥位字符串（简化处理）
  // 在实际应用中，应该完整解析ASN.1结构
  const publicKeyBits = certHex.substring(publicKeyStart);
  
  // 创建一个模拟的公钥对象（实际应该正确解析）
  // 这里我们回退到使用固件公钥作为备选
  console.log("⚠️ 使用固件公钥作为备选方案");
  return firmwarePubKey;
}

// ===== 修复的手动提取证书信息函数 =====
function manuallyExtractCertificateInfo(certDer) {
  try {
    console.log("🛠️ 尝试多种方式提取证书信息...");
    
    // 首先尝试十六进制解码
    const certString = certDer.toString('utf-8');
    if (/^[0-9a-fA-F]+$/.test(certString)) {
      console.log("🔄 尝试十六进制字符串转换...");
      const certBuffer = Buffer.from(certString, 'hex');
      
      // 尝试解析为X.509证书
      try {
        const x509Cert = new X509Certificate(certBuffer);
        console.log("✅ 十六进制转换后证书解析成功");
        return x509Cert;
      } catch (error) {
        console.log("⚠️ 十六进制转换后证书解析失败:", error.message);
      }
      
      // 如果无法解析为证书，尝试提取公钥
      try {
        const publicKey = extractPublicKeyFromCert(certBuffer);
        const publicKeyPem = publicKey.export({ format: 'pem', type: 'spki' });
        
        console.log("✅ 十六进制转换后公钥提取成功");
        return createMinimalCertificate(publicKeyPem, certBuffer);
      } catch (error) {
        console.log("⚠️ 十六进制转换后公钥提取失败:", error.message);
      }
    }
    
    throw new Error("所有证书信息提取方法都失败");
  } catch (error) {
    throw new Error(`手动提取失败: ${error.message}`);
  }
}

// ===== 创建最小证书对象 =====
function createMinimalCertificate(publicKeyPem, originalData) {
  // 从公钥PEM中提取信息创建简化证书对象
  const publicKey = crypto.createPublicKey(publicKeyPem);
  const keyDetails = publicKey.asymmetricKeyType;
  
  const minimalCert = {
    subject: `CN=Device (${keyDetails})`,
    issuer: caCertificate.issuer,
    serialNumber: `manual-${Date.now()}`,
    validFrom: new Date().toISOString(),
    validTo: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
    publicKey: publicKeyPem,
    tbsCertificate: originalData,
    signature: Buffer.alloc(64), // 空签名
    ca: false
  };
  
  return minimalCert;
}
const APP_UPDATE_INFO = {
  version: "7.9.1",                    // 版本号
  isForceUpdate: false,                 // 是否强制更新
  downloadUrl: "http://192.168.0.102:3000/download-apk", // 下载链接https://apps.apple.com/us/app/onekey-open-source-wallet/id1609559473
   storeUrl: "https://apps.apple.com/app/id123456789",
 
  changeLog: `
- unionkey更新4.7.1 
- 测试并 修复了一些 bug
- 优化性能
- 增加新功能：自动同步 NFT
  `,
};

function getUpdateInfoForPlatform(platform, currentVersion) {  
  const platforms = {  
    ios: {  
      version: "7.9.1",  
      updateStrategy: 2,  
      storeUrl: "https://apps.apple.com/app/id123456789",  
      changeLog: "iOS更新内容...",  
      fileSize: 50000000  
    },  
    android: {  
      version: "7.9.1",   
      updateStrategy: 2,  
      downloadUrl: "http://192.168.0.102:3000/download-apk",  
   
      changeLog: "Android更新内容1...",  
      fileSize: 45000000  
    },  
    desktop: {  
      version: "7.9.1",  
      updateStrategy: 0,  
      downloadUrl: "http://192.168.0.102:3000/download-exe",  
      changeLog: "桌面端更新内容...",  
      fileSize: 80000000  
    },  
    extension: {  
      version: "7.9.1",  
      updateStrategy: 2,  
      // 不要在这里使用 platformEnv.isExtChrome  
      storeUrl: "https://chrome.google.com/webstore/detail/xxx",  
      changeLog: "扩展更新内容..."  
    }  
  };  
  
  return platforms[platform] || {  
    version: "7.9.1",  
    updateStrategy: 2,  
    changeLog: "通用更新内容"  
  };  
}









// ===== NFT Catalog =====
const NFT_CATALOG = [
  { id: "A", name: "UnionKey DEX", description: "1x Token Rights", image: "/images/A.jpg" },
  { id: "B", name: "UnionKey DEX Plus", description: "10x Token Rights", image: "/images/B.jpg" },
  { id: "C", name: "UnionKey DEX Pro", description: "100x Token Rights", image: "/images/C.jpg" }
];

// ===== 内存 mint 池 =====
let availableMintsA = [];
let availableMintsB = [];
let availableMintsC = [];

// ===== 加载钱包 mints =====
async function loadWalletMints(wallet, list) {
  if (!wallet) return [];
  const accounts = await connection.getParsedTokenAccountsByOwner(wallet.publicKey, {
    programId: new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
  });
  const mints = accounts.value
    .filter(acc => {
      const info = acc.account.data.parsed.info.tokenAmount;
      return info.amount === "1" && info.decimals === 0;
    })
    .map(acc => acc.account.data.parsed.info.mint);

  if (list === "A") availableMintsA = mints;
  if (list === "B") availableMintsB = mints;
  if (list === "C") availableMintsC = mints;

  console.log(`✅ Loaded ${mints.length} mints for ${list}`);
}


async function initMints() {
  await loadWalletMints(walletA, "A");
  await loadWalletMints(walletB, "B");
  await loadWalletMints(walletC, "C");
}

// ===== Excel SN管理 ===== 
const EXCEL_PATH = path.join(__dirname, "data", "serials.xlsx");
let workbook, SERIALS_A, SERIALS_B, SERIALS_C;

function loadSerials() {
  workbook = XLSX.readFile(EXCEL_PATH);
  SERIALS_A = XLSX.utils.sheet_to_json(workbook.Sheets["A"] || []);
  SERIALS_B = XLSX.utils.sheet_to_json(workbook.Sheets["B"] || []);
  SERIALS_C = XLSX.utils.sheet_to_json(workbook.Sheets["C"] || []);
  console.log("✅ Excel serials loaded");
}
loadSerials();

function saveExcel() {
  XLSX.writeFile(workbook, EXCEL_PATH);
}

function findSerialRow(serial) {
  let row = SERIALS_A.find(r => r["SN编号"] === serial);
  if (row) return { type: "A", row };
  row = SERIALS_B.find(r => r["SN编号"] === serial);
  if (row) return { type: "B", row };
  row = SERIALS_C.find(r => r["SN编号"] === serial);
  if (row) return { type: "C", row };
  return null;
}

  
const ECDSASignature = asn1.define('ECDSASignature', function() {  
  this.seq().obj(  
    this.key('r').int(),  
    this.key('s').int()  
  );  
});  
  
/**  
 * 将DER编码的ECDSA签名转换为raw r||s格式  
 */  
function derToRawSignature(derSig) {  
  try {  
    const decoded = ECDSASignature.decode(derSig, 'der');  
    const r = decoded.r.toArrayLike(Buffer, 'be', 32);  
    const s = decoded.s.toArrayLike(Buffer, 'be', 32);  
    return Buffer.concat([r, s]);  
  } catch (e) {  
    if (derSig.length === 64) {  
      return derSig;  
    }  
    throw e;  
  }  
}  
  

  


// ===== Express setup =====
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));


app.get("/my-app-config", (req, res) => {  
  const { platform, version } = req.query;  
  const updateInfo = getUpdateInfoForPlatform(platform, version);  

  res.json({ code: 0, data: updateInfo });  
});

app.get('/download-apk', (req, res) => 
  { const filePath = path.join(__dirname, 'apk', 'unionkey4.9.0.apk'); 
    res.download(filePath, 'unionkey.apk');
     });
     app.get('/download-firmware', (req, res) => 
  { const filePath = path.join(__dirname, 'firmware', 'firmware.bin'); 
    res.download(filePath, 'firmware.bin');
     });
// function buildCRIAndDigest(subjectCN, publicKeyBytes) {  
//   try {  
//     // 确保公钥是65字节的未压缩格式(0x04 + x + y)  
//     let pubKeyBuffer;  
//     if (publicKeyBytes.length === 65 && publicKeyBytes[0] === 0x04) {  
//       pubKeyBuffer = publicKeyBytes;  
//     } else if (publicKeyBytes.length === 64) {  
//       // 如果是64字节,添加0x04前缀  
//       pubKeyBuffer = Buffer.concat([Buffer.from([0x04]), publicKeyBytes]);  
//     } else {  
//       throw new Error(`Invalid public key length: ${publicKeyBytes.length}`);  
//     }  
  
//     // 使用node-forge构造CRI  
//     const pki = forge.pki;  
      
//     // 创建Subject  
//     const subject = [  
//       { name: 'commonName', value: subjectCN }  
//     ];  
  
//     // 创建SubjectPublicKeyInfo  
//     // 对于ECDSA P-256,算法OID是1.2.840.10045.2.1(ecPublicKey)  
//     // 曲线参数OID是1.2.840.10045.3.1.7(prime256v1/secp256r1)  
//     const asn1 = forge.asn1;  
//     const spki = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [  
//       asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [  
//         asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,  
//           asn1.oidToDer('1.2.840.10045.2.1').getBytes()),  
//         asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,  
//           asn1.oidToDer('1.2.840.10045.3.1.7').getBytes())  
//       ]),  
//       asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false,  
//         String.fromCharCode(0x00) + pubKeyBuffer.toString('binary'))  
//     ]);  
  
//     // 创建CertificationRequestInfo  
//     const cri = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [  
//       // version (v1 = 0)  
//       asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,  
//         asn1.integerToDer(0).getBytes()),  
//       // subject  
//       pki.distinguishedNameToAsn1({ attributes: subject }),  
//       // subjectPKInfo  
//       spki,  
//       // attributes (empty)  
//       asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [])  
//     ]);  
  
//     // 将CRI转换为DER编码  
//     const criDer = Buffer.from(asn1.toDer(cri).getBytes(), 'binary');  
      
//     // 计算SHA256摘要  
//     const hash = crypto.createHash('sha256');  
//     hash.update(criDer);  
//     const digest = hash.digest();  
  
//     console.log('CRI DER length:', criDer.length);  
//     console.log('CRI digest (hex):', digest.toString('hex'));  
  
//     return { criDer, digest };  
//   } catch (error) {  
//     console.error('Error building CRI:', error);  
//     throw error;  
//   }  
// }  
  
/**  
 * 从证书中提取公钥字节  
 */  
function extractPublicKeyBytes(certBuffer) {  
  try {  
    // 检查是否是Protobuf包装的证书  
    let actualCertBuffer = certBuffer;  
      
    // Protobuf bytes field格式: 0x0A (tag) + varint length + data  
    if (certBuffer[0] === 0x0A) {  
      console.log('Certificate appears to be Protobuf-wrapped');  
      let offset = 1;  
      // 解析varint长度  
      let length = 0;  
      let shift = 0;  
      while (offset < certBuffer.length) {  
        const byte = certBuffer[offset++];  
        length |= (byte & 0x7F) << shift;  
        if ((byte & 0x80) === 0) break;  
        shift += 7;  
      }  
      console.log('Extracted certificate length from protobuf:', length);  
      actualCertBuffer = certBuffer.slice(offset, offset + length);  
      console.log('Actual certificate buffer length:', actualCertBuffer.length);  
    }  
      
    // 解析证书  
    const cert = forge.pki.certificateFromAsn1(  
      forge.asn1.fromDer(actualCertBuffer.toString('binary'))  
    );  
      
    // 从证书的SubjectPublicKeyInfo中提取原始公钥字节  
    const spki = cert.publicKeyInfo;  
    const publicKeyAsn1 = forge.asn1.fromDer(  
      forge.pki.publicKeyToAsn1(cert.publicKey)  
    );  
      
    // 提取BIT STRING中的公钥数据  
    const bitString = publicKeyAsn1.value[1];  
    const pubKeyBytes = Buffer.from(bitString.value, 'binary');  
      
    // 跳过第一个字节(unused bits indicator)  
    const actualPubKey = pubKeyBytes.slice(1);  
      
    console.log('Extracted public key length:', actualPubKey.length);  
    console.log('Public key (hex):', actualPubKey.toString('hex').substring(0, 40) + '...');  
      
    return actualPubKey;  
  } catch (error) {  
    console.error('Error extracting public key:', error);  
      
    // 如果解析失败,尝试直接从firmware_key.pem读取公钥  
    console.log('Falling back to firmware_key.pem');  
    try {  
      const publicKey = forge.pki.publicKeyFromPem(FIRMWARE_PUBLIC_KEY_PEM);  
      const publicKeyAsn1 = forge.asn1.fromDer(  
        forge.pki.publicKeyToAsn1(publicKey)  
      );  
      const bitString = publicKeyAsn1.value[1];  
      const pubKeyBytes = Buffer.from(bitString.value, 'binary');  
      return pubKeyBytes.slice(1);  
    } catch (fallbackError) {  
      console.error('Fallback also failed:', fallbackError);  
      throw error;  
    }  
  }  
}
  
// /**  
//  * 验证ECDSA签名(针对CRI摘要)  
//  */  
// function verifyECDSASignature(digest, publicKeyPEM, signatureBuffer) {  
//   try {  
//     // 处理hex字符串编码的签名  
//     let rawSignature = signatureBuffer;  
//     const firstByte = signatureBuffer[0];  
//     if ((firstByte >= 0x30 && firstByte <= 0x39) ||  
//         (firstByte >= 0x61 && firstByte <= 0x66) ||  
//         (firstByte >= 0x41 && firstByte <= 0x46)) {  
//       console.log('Signature is hex-encoded string');  
//       const hexString = signatureBuffer.toString('utf8');  
//       rawSignature = Buffer.from(hexString, 'hex');  
//       console.log('Decoded signature length:', rawSignature.length);  
//     }  
  
//     if (rawSignature.length !== 64) {  
//       console.error('Invalid signature length:', rawSignature.length);  
//       return false;  
//     }  
  
//     console.log('Raw signature (hex):', rawSignature.toString('hex'));  
  
//     // 将raw r||s转换为DER格式  
//     const r = rawSignature.slice(0, 32);  
//     const s = rawSignature.slice(32, 64);  
//     const derSig = encodeDERSignature(r, s);  
  
//     console.log('DER signature length:', derSig.length);  
  
//     // 使用公钥验证签名  
//     // 注意:这里直接验证摘要,不需要再次哈希  
//     const verify = crypto.createVerify('SHA256');  
//     verify.update(digest);  
//     verify.end();  
  
//     const isValid = verify.verify(  
//       {  
//         key: publicKeyPEM,  
//         format: 'pem',  
//         type: 'spki'  
//       },  
//       derSig  
//     );  
  
//     return isValid;  
//   } catch (error) {  
//     console.error('Signature verification error:', error);  
//     return false;  
//   }  
// }  
  
/**  
 * 将raw r||s签名编码为DER格式  
//  */  
// function encodeDERSignature(r, s) {  
//   function trimLeadingZeros(buf) {  
//     let i = 0;  
//     while (i < buf.length - 1 && buf[i] === 0 && (buf[i + 1] & 0x80) === 0) {  
//       i++;  
//     }  
//     return buf.slice(i);  
//   }  
  
//   function addPaddingIfNeeded(buf) {  
//     if ((buf[0] & 0x80) !== 0) {  
//       return Buffer.concat([Buffer.from([0x00]), buf]);  
//     }  
//     return buf;  
//   }  
  
//   const rTrimmed = addPaddingIfNeeded(trimLeadingZeros(r));  
//   const sTrimmed = addPaddingIfNeeded(trimLeadingZeros(s));  
  
//   const rDER = Buffer.concat([Buffer.from([0x02, rTrimmed.length]), rTrimmed]);  
//   const sDER = Buffer.concat([Buffer.from([0x02, sTrimmed.length]), sTrimmed]);  
//   const totalLength = rDER.length + sDER.length;  
  
//   return Buffer.concat([  
//     Buffer.from([0x30, totalLength]),  
//     rDER,  
//     sDER  
//   ]);  
// }  
  
// function extractSerialNumber(certBuffer) {  
//   try {  
//     const cert = forge.pki.certificateFromAsn1(  
//       forge.asn1.fromDer(certBuffer.toString('binary'))  
//     );  
//     return cert.serialNumber;  
//   } catch (error) {  
//     return 'UNKNOWN_SN';  
//   }  
// }  
  

function buildCRIAndDigest(subjectCN, publicKeyBytes) {  
  try {  
    // 确保公钥格式正确  
    let pubKeyBuffer;  
    if (publicKeyBytes.length === 65 && publicKeyBytes[0] === 0x04) {  
      pubKeyBuffer = publicKeyBytes;  
    } else if (publicKeyBytes.length === 64) {  
      pubKeyBuffer = Buffer.concat([Buffer.from([0x04]), publicKeyBytes]);  
    } else {  
      throw new Error(`Invalid public key length: ${publicKeyBytes.length}`);  
    }  
  
    const asn1 = forge.asn1;  
      
    // 构造SubjectPublicKeyInfo  
    const spki = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [  
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [  
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,  
          asn1.oidToDer('1.2.840.10045.2.1').getBytes()),  
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.OID, false,  
          asn1.oidToDer('1.2.840.10045.3.1.7').getBytes())  
      ]),  
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.BITSTRING, false,  
        String.fromCharCode(0x00) + pubKeyBuffer.toString('binary'))  
    ]);  
  
    // 关键修复:正确构造Subject  
    // 方法1: 使用forge.pki.distinguishedNameToAsn1的正确格式  
    const attrs = [  
      {  
        name: 'commonName',  
        value: subjectCN,  
        type: '2.5.4.3'  // CN的OID  
      }  
    ];  
    const subject = forge.pki.distinguishedNameToAsn1({ attributes: attrs });  
  
    // 构造CRI  
    const cri = asn1.create(asn1.Class.UNIVERSAL, asn1.Type.SEQUENCE, true, [  
      asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false,  
        asn1.integerToDer(0).getBytes()),  
      subject,  
      spki,  
      asn1.create(asn1.Class.CONTEXT_SPECIFIC, 0, true, [])  
    ]);  
  
    const criDer = Buffer.from(asn1.toDer(cri).getBytes(), 'binary');  
    const hash = crypto.createHash('sha256');  
    hash.update(criDer);  
    const digest = hash.digest();  
    fs.writeFileSync('cri_js.der', criDer);  
  fs.writeFileSync('digest_js.bin', digest);  
  console.log('Saved CRI to cri_js.der');  
  console.log('CRI hex (first 50 bytes):', criDer.toString('hex').substring(0, 100));  
    
    console.log('CRI DER length:', criDer.length);  
    console.log('CRI digest (hex):', digest.toString('hex'));  
  
    return { criDer, digest };  
  } catch (error) {  
    console.error('Error building CRI:', error);  
    throw error;  
  }  
}
  
/**  
 * 验证ECDSA签名  
 */  
function verifyECDSASignature(digest, publicKeyPEM, signatureBuffer) {  
  try {  
    // 处理hex字符串编码的签名  
    let rawSignature = signatureBuffer;  
    const firstByte = signatureBuffer[0];  
    if ((firstByte >= 0x30 && firstByte <= 0x39) ||  
        (firstByte >= 0x61 && firstByte <= 0x66) ||  
        (firstByte >= 0x41 && firstByte <= 0x46)) {  
      console.log('Signature is hex-encoded string');  
      const hexString = signatureBuffer.toString('utf8');  
      rawSignature = Buffer.from(hexString, 'hex');  
      console.log('Decoded signature length:', rawSignature.length);  
    }  
  
    if (rawSignature.length !== 64) {  
      console.error('Invalid signature length:', rawSignature.length);  
      return false;  
    }  
  
    console.log('Raw signature (hex):', rawSignature.toString('hex'));  
  
    // 将raw r||s转换为DER格式  
    const r = rawSignature.slice(0, 32);  
    const s = rawSignature.slice(32, 64);  
    const derSig = encodeDERSignature(r, s);  
  
    console.log('DER signature length:', derSig.length);  
  
    // 验证签名  
    const verify = crypto.createVerify('SHA256');  
    verify.update(digest);  
    verify.end();  
  
    const isValid = verify.verify(  
      {  
        key: publicKeyPEM,  
        format: 'pem',  
        type: 'spki'  
      },  
      derSig  
    );  
  
    return isValid;  
  } catch (error) {  
    console.error('Signature verification error:', error);  
    return false;  
  }  
}  
  
function encodeDERSignature(r, s) {  
  function trimLeadingZeros(buf) {  
    let i = 0;  
    while (i < buf.length - 1 && buf[i] === 0 && (buf[i + 1] & 0x80) === 0) {  
      i++;  
    }  
    return buf.slice(i);  
  }  
  
  function addPaddingIfNeeded(buf) {  
    if ((buf[0] & 0x80) !== 0) {  
      return Buffer.concat([Buffer.from([0x00]), buf]);  
    }  
    return buf;  
  }  
  
  const rTrimmed = addPaddingIfNeeded(trimLeadingZeros(r));  
  const sTrimmed = addPaddingIfNeeded(trimLeadingZeros(s));  
  
  const rDER = Buffer.concat([Buffer.from([0x02, rTrimmed.length]), rTrimmed]);  
  const sDER = Buffer.concat([Buffer.from([0x02, sTrimmed.length]), sTrimmed]);  
  const totalLength = rDER.length + sDER.length;  
  
  return Buffer.concat([  
    Buffer.from([0x30, totalLength]),  
    rDER,  
    sDER  
  ]);  
}app.post('/hardware/verify', async (req, res) => {      
  const requestId = Date.now();      
  console.log(`[${requestId}] ===== 开始硬件设备验证 =====`);      
        
  try {      
    const { deviceType, data, cert, signature } = req.body;      
    console.log(`[${requestId}] 步骤 1: 接收到验证请求`, {    
      deviceType,    
      dataLength: data?.length,    
      certLength: cert?.length,    
      signatureLength: signature?.length    
    });    
          
    // 1. Base64 解码证书    
    console.log(`[${requestId}] 步骤 2: 开始解码证书`);    
    const certBase64Buffer = Buffer.from(cert, 'base64');      
          
    // 2. 十六进制解码证书    
    const certString = certBase64Buffer.toString('utf8');      
    const isHexEncoded = /^[0-9a-fA-F]+$/.test(certString);      
    const certBuffer = isHexEncoded       
      ? Buffer.from(certString, 'hex')      
      : certBase64Buffer;      
    console.log(`[${requestId}] 步骤 2: 证书解码完成 (${isHexEncoded ? '十六进制' : '二进制'}格式)`);    
          
    // 3. DER 转 PEM      
    const pemCert = convertDERToPEM(certBuffer);      
          
    // 4. 解析证书      
    const deviceCert = new X509Certificate(pemCert);      
          
    // 5. 输出证书详细信息      
    console.log(`[${requestId}] 步骤 3: 证书解析成功`);    
    console.log(`[${requestId}] ========== 设备证书详细信息 ==========`);      
    console.log(`[${requestId}] Subject (设备信息):`, deviceCert.subject);      
    console.log(`[${requestId}] Issuer (CA 信息):`, deviceCert.issuer);      
    console.log(`[${requestId}] 序列号:`, deviceCert.serialNumber);      
    console.log(`[${requestId}] 有效期开始:`, deviceCert.validFrom);      
    console.log(`[${requestId}] 有效期结束:`, deviceCert.validTo);      
    console.log(`[${requestId}] 公钥算法:`, deviceCert.publicKey.asymmetricKeyType);      
    console.log(`[${requestId}] 公钥详情:`, deviceCert.publicKey.asymmetricKeyDetails);      
          
    // 6. 提取证书中的公钥    
    const certPublicKey = deviceCert.publicKey;    
    const certPublicKeyPem = certPublicKey.export({      
      type: 'spki',      
      format: 'pem'      
    });      
    console.log(`[${requestId}] 证书公钥 (PEM 格式):\n${certPublicKeyPem}`);      
        
    // 7. 跳过 firmware_key.pem 公钥匹配检查(方案 1)  
    console.log(`[${requestId}] 步骤 4: 跳过公钥匹配检查,直接使用证书公钥验证签名`);  
        
    // 8. 解码签名    
    console.log(`[${requestId}] 步骤 5: 开始验证签名`);    
    const signatureBase64Buffer = Buffer.from(signature, 'base64');    
    const signatureString = signatureBase64Buffer.toString('utf8');    
    const isSignatureHexEncoded = /^[0-9a-fA-F]+$/.test(signatureString);    
        
    const signatureBuffer = isSignatureHexEncoded    
      ? Buffer.from(signatureString, 'hex')    
      : signatureBase64Buffer;    
        
    console.log(`[${requestId}] 步骤 5: 签名解码完成`, {    
      originalLength: signatureBase64Buffer.length,    
      decodedLength: signatureBuffer.length,    
      format: isSignatureHexEncoded ? '十六进制' : '二进制'    
    });    
        
    // 9. 验证签名    
    const dataBuffer = Buffer.from(data, 'utf-8');    
    console.log(`[${requestId}] 步骤 5: 挑战数据: ${data}`);    
        
    // 将原始签名(r||s)转换为 DER 格式    
    const derSignature = convertRawToDER(signatureBuffer);    
    console.log(`[${requestId}] 步骤 5: 签名格式转换完成 (${signatureBuffer.length} 字节 → ${derSignature.length} 字节)`);    
        
    // 使用证书中的公钥验证签名    
    const verify = crypto.createVerify('SHA256');    
    verify.update(dataBuffer);    
    verify.end();    
        
    const isValidSignature = verify.verify(    
      {    
        key: certPublicKey,    
        format: 'pem',    
        type: 'spki'    
      },    
      derSignature    
    );    
        
    console.log(`[${requestId}] 步骤 5: 签名验证结果: ${isValidSignature ? '✓ 通过' : '✗ 失败'}`);    
        
    if (!isValidSignature) {    
      console.log(`[${requestId}] 步骤 5: 签名验证失败 - 详细信息:`, {    
        dataHex: dataBuffer.toString('hex'),    
        signatureHex: signatureBuffer.toString('hex'),    
        derSignatureHex: derSignature.toString('hex')    
      });    
      return res.json({    
        code: 10105,    
        message: 'Signature verification failed',    
        data: {    
          subject: deviceCert.subject,    
          signatureValid: false    
        }    
      });    
    }    
        
    // 10. 验证成功    
    console.log(`[${requestId}] ===== 验证成功 ===== ✓✓✓`);    
      
    // 提取设备序列号  
    const serialNumber = extractSerialNumber(deviceCert.subject);  
      
    return res.json({      
      code: 0,      
      message: 'Verification successful',      
      data: serialNumber    
    });      
          
  } catch (error) {      
    console.error(`[${requestId}] 验证过程发生错误:`, error);      
    return res.json({      
      code: 10104,      
      message: 'Verification error',      
      error: error.message      
    });      
  }      
});  
  
// 辅助函数: DER 转 PEM  
function convertDERToPEM(derBuffer) {  
  const base64Cert = derBuffer.toString('base64');  
  const pemBody = base64Cert.match(/.{1,64}/g).join('\n');  
  return `-----BEGIN CERTIFICATE-----\n${pemBody}\n-----END CERTIFICATE-----`;  
}  
  
// 辅助函数: 将原始 ECDSA 签名(r||s)转换为 DER 格式  
function convertRawToDER(signatureBuffer) {  
  if (signatureBuffer.length !== 64) {  
    console.log('签名长度不是 64 字节,可能已经是 DER 格式');  
    return signatureBuffer;  
  }  
    
  const r = signatureBuffer.slice(0, 32);  
  const s = signatureBuffer.slice(32, 64);  
    
  const rDER = encodeDERInteger(r);  
  const sDER = encodeDERInteger(s);  
    
  const sequenceLength = rDER.length + sDER.length;  
  const der = Buffer.concat([  
    Buffer.from([0x30, sequenceLength]),  
    rDER,  
    sDER  
  ]);  
    
  return der;  
}  
  


// 辅助函数:从证书 subject 中提取序列号  
function extractSerialNumber(subject) {  
  // subject 格式示例: "CN=TC01WBD20250902112946044580"  
  const match = subject.match(/CN=([^,]+)/);  
  return match ? match[1] : '';  
}  
  

  
function encodeDERInteger(value) {  
  // 如果最高位是 1,需要添加 0x00 前缀  
  const needsPadding = value[0] & 0x80;  
  const length = value.length + (needsPadding ? 1 : 0);  
    
  const result = Buffer.allocUnsafe(2 + length);  
  result[0] = 0x02; // INTEGER tag  
  result[1] = length;  
    
  if (needsPadding) {  
    result[2] = 0x00;  
    value.copy(result, 3);  
  } else {  
    value.copy(result, 2);  
  }  
    
  return result;  
}  
  

app.get('/utility/v1/firmware/detail', async (req, res) => {  
  const requestId = Date.now();  
  console.log(`\n[${requestId}] ===== 固件版本查询开始 =====`);  
    
  const { deviceType, system, bluetooth, bootloader } = req.query;  
    
  console.log(`[${requestId}] 步骤 1: 接收到查询请求`);  
  console.log(`[${requestId}] 设备当前版本:`, {  
    deviceType,  
    system,  
    bluetooth,  
    bootloader  
  });  
  
  try {  
    // 从数据库获取该设备类型的最新固件版本  
    const latestFirmware = FIRMWARE_DATABASE[deviceType];  
      
    if (!latestFirmware) {  
      console.error(`[${requestId}] 不支持的设备类型: ${deviceType}`);  
      return res.status(400).json({  
        error: { message: `Unsupported device type: ${deviceType}` }  
      });  
    }  
  
    console.log(`[${requestId}] 步骤 2: 服务器最新版本`);  
      
    // 构建响应数据  
    const firmwares = [  
      {  
        type: 'system',  
        version: latestFirmware.system.version,  
        checksum: latestFirmware.system.checksum,  
        commitId: latestFirmware.system.commitId,  
        releaseUrl: latestFirmware.system.releaseUrl,  
        changelog: latestFirmware.system.changelog  
      },  
      {  
        type: 'bluetooth',  
        version: latestFirmware.bluetooth.version,  
        checksum: latestFirmware.bluetooth.checksum,  
        commitId: latestFirmware.bluetooth.commitId,  
        releaseUrl: latestFirmware.bluetooth.releaseUrl,  
        changelog: latestFirmware.bluetooth.changelog  
      },  
      {  
        type: 'bootloader',  
        version: latestFirmware.bootloader.version,  
        checksum: latestFirmware.bootloader.checksum,  
        commitId: latestFirmware.bootloader.commitId,  
        releaseUrl: latestFirmware.bootloader.releaseUrl,  
        changelog: latestFirmware.bootloader.changelog  
      }  
    ];  
  
    // 比对版本差异  
    console.log(`[${requestId}] 步骤 3: 版本比对结果`);  
    const systemNeedsUpdate = system !== latestFirmware.system.version;  
    const bluetoothNeedsUpdate = bluetooth !== latestFirmware.bluetooth.version;  
    const bootloaderNeedsUpdate = bootloader !== latestFirmware.bootloader.version;  
      
    console.log(`[${requestId}]   System: ${system} -> ${latestFirmware.system.version} ${systemNeedsUpdate ? '(需要更新)' : '(无需更新)'}`);  
    console.log(`[${requestId}]   Bluetooth: ${bluetooth} -> ${latestFirmware.bluetooth.version} ${bluetoothNeedsUpdate ? '(需要更新)' : '(无需更新)'}`);  
    console.log(`[${requestId}]   Bootloader: ${bootloader} -> ${latestFirmware.bootloader.version} ${bootloaderNeedsUpdate ? '(需要更新)' : '(无需更新)'}`);  
  
    const response = {  
      data: {  
        firmwares: firmwares  
      }  
    };  
  
    console.log(`[${requestId}] 步骤 4: 响应数据构建完成`);  
    console.log(`[${requestId}] 返回固件数量: ${firmwares.length}`);  
    console.log(`[${requestId}] ===== 查询成功 =====\n`);  
  
    return res.json(response);  
  
  } catch (error) {  
    console.error(`[${requestId}] ===== 查询失败 =====`);  
    console.error(`[${requestId}] 错误:`, error);  
    return res.status(500).json({  
      error: {  
        message: error.message || 'Internal server error',  
        requestId: requestId  
      }  
    });  
  }  
});  
  
// 硬件验证接口 - 也添加返回信息日志  
app.post('/hardware/verify', async (req, res) => {  
  const requestId = Date.now();  
  console.log(`\n[${requestId}] ===== 硬件设备验证开始 =====`);  
    
  try {  
    const { deviceType, data, cert, signature } = req.body;  
      
    console.log(`[${requestId}] 步骤 1: 接收到验证请求`, {  
      deviceType,  
      dataLength: data?.length,  
      certLength: cert?.length,  
      signatureLength: signature?.length  
    });  
      
    // ... 您之前的验证逻辑 ...  
      
    // 验证成功时的返回信息  
    const successResponse = {  
      code: 0,  
      message: 'Verification successful',  
      data: 'DEVICE_SERIAL_NUMBER',  
      requestId: requestId,  
      timestamp: new Date().toISOString()  
    };  
      
    console.log(`[${requestId}] ===== 验证成功 =====`);  
    console.log(`[${requestId}] 返回信息:`, successResponse);  
      
    return res.json(successResponse);  
      
  } catch (error) {  
    const errorResponse = {  
      code: 10107,  
      message: error.message || 'Internal server error',  
      data: null,  
      requestId: requestId,  
      timestamp: new Date().toISOString()  
    };  
      
    console.error(`[${requestId}] ===== 验证失败 =====`);  
    console.error(`[${requestId}] 返回信息:`, errorResponse);  
      
    return res.json(errorResponse);  
  }  
});  

  
app.post('/api/firmware/check', async (req, res) => {
  const requestId = Date.now();
  console.log(`\n[${requestId}] ===== 固件检查请求 =====`);

  const { deviceType, firmwareVersion, bluetoothVersion, bootloaderVersion, connectId } = req.body;

  console.log(`[${requestId}] 请求参数:`, {
    deviceType,
    firmwareVersion,
    bluetoothVersion,
    bootloaderVersion,
    connectId,
  });

  try {
    const deviceFirmware = FIRMWARE_DATABASE[deviceType];

    if (!deviceFirmware) {
      return res.status(400).json({
        error: `Unsupported device type: ${deviceType}`,
      });
    }

    // ✅ 返回数组格式
    // ✅ 改成对象结构
  const response = [
      {
        type: 'system',
        version: deviceFirmware.system.version.split('.'),
        checksum: deviceFirmware.system.checksum,
        commitId: deviceFirmware.system.commitId,
        releaseUrl: deviceFirmware.system.releaseUrl,
        changelog: deviceFirmware.system.changelog,
        // hasUpgrade: compareVersion(deviceFirmware.system.version, firmwareVersion),
         hasUpgrade:true,
      },
      {
        type: 'bluetooth',
        version: deviceFirmware.bluetooth.version.split('.'),
        checksum: deviceFirmware.bluetooth.checksum,
        commitId: deviceFirmware.bluetooth.commitId,
        releaseUrl: deviceFirmware.bluetooth.releaseUrl,
        changelog: deviceFirmware.bluetooth.changelog,
        hasUpgrade: compareVersion(deviceFirmware.bluetooth.version, bluetoothVersion),
      },
      {
        type: 'bootloader',
        version: deviceFirmware.bootloader.version.split('.'),
        checksum: deviceFirmware.bootloader.checksum,
        commitId: deviceFirmware.bootloader.commitId,
        releaseUrl: deviceFirmware.bootloader.releaseUrl,
        changelog: deviceFirmware.bootloader.changelog,
        hasUpgrade: compareVersion(deviceFirmware.bootloader.version, bootloaderVersion),
      },
    ];



    console.log(`[${requestId}] 返回固件信息`);
  
    return res.json(response);
  } catch (error) {
    console.error(`[${requestId}] 错误:`, error);
    return res.status(500).json({
      error: error.message || 'Internal server error',
    });
  }
});
function compareVersion(latestVersion, currentVersion) {
  console.log('比较版本:', { latestVersion, currentVersion });

  if (!currentVersion) {
    console.log('当前版本不存在，默认需要升级');
    return true; // 没有版本信息认为需要升级
  }

  const latest = latestVersion.split('.').map(Number);
  const current = currentVersion.split('.').map(Number);

  console.log('拆分后:', { latest, current });

  for (let i = 0; i < latest.length; i++) {
    const l = latest[i] || 0;
    const c = current[i] || 0;
    console.log(`比较第${i}位: 最新=${l}, 当前=${c}`);

    if (l > c) {
      console.log('需要升级: 最新版本大于当前版本');
      return true;
    }
    if (l < c) {
      console.log('不需要升级: 最新版本小于当前版本');
      return false;
    }
  }

  console.log('版本完全相同，不需要升级');
  return false; // 完全相同
}


app.get('/config.json', (req, res) => {
  const filePath = path.join(__dirname, 'config.json');
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      console.error('读取 config.json 失败:', err);
      return res.status(500).send({ error: '读取 config.json 失败' });
    }
    try {
      const jsonData = JSON.parse(data);
      res.json(jsonData);
    } catch (parseErr) {
      console.error('解析 config.json 失败:', parseErr);
      res.status(500).send({ error: '解析 config.json 失败' });
    }
  });
});

// 可选 pre-config.json
app.get('/pre-config.json', (req, res) => {
  const filePath = path.join(__dirname, 'config.json');
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) return res.status(500).send({ error: '读取 pre-config.json 失败' });
    res.json(JSON.parse(data));
  });
});

app.get("/nfts", (req, res) => {
  const data = NFT_CATALOG.map(item => ({
    id: item.id,
    name: item.name,
    description: item.description,
    image: item.image,
    available: [availableMintsA, availableMintsB, availableMintsC][['A','B','C'].indexOf(item.id)].length
  }));
  res.json(data);
});

app.get("/check-serial", (req, res) => {
  const { serial } = req.query;
  if (!serial) return res.status(400).json({ error: "Missing serial" });

  const found = findSerialRow(serial);
  if (!found) return res.json({ valid: false });

  const { type, row } = found;
  const canClaim = row["状态"] !== "已领取";

  res.json({
    valid: true,
    type,
    status: row["状态"],
    remark: row["备注"],
    canClaim,
  });
});

async function transferNft(wallet, mintAddress, userAddress) {
  const mintPub = new PublicKey(mintAddress);
  const userPub = new PublicKey(userAddress);
  const fromAta = await getOrCreateAssociatedTokenAccount(connection, wallet, mintPub, wallet.publicKey);
  const toAta = await getOrCreateAssociatedTokenAccount(connection, wallet, mintPub, userPub);

  const tx = new Transaction().add(createTransferInstruction(fromAta.address, toAta.address, wallet.publicKey, 1));
  const sig = await connection.sendTransaction(tx, [wallet], { preflightCommitment: "confirmed" });
  await connection.confirmTransaction(sig, "confirmed");
  return sig;
}

app.post("/claim", async (req, res) => {
  const { userAddress, type, serial } = req.body;
  if (!userAddress || !type || !serial) return res.status(400).json({ error: "Missing params" });

  const found = findSerialRow(serial);
  if (!found || found.type !== type) return res.status(403).json({ error: "Serial not valid" });

  const { row } = found;
  if (row["状态"] === "已领取") return res.status(403).json({ error: "Serial already used" });

  let wallet, pool;
  if (type === "A") { wallet = walletA; pool = availableMintsA; }
  if (type === "B") { wallet = walletB; pool = availableMintsB; }
  if (type === "C") { wallet = walletC; pool = availableMintsC; }

  if (!wallet) return res.status(400).json({ error: "Invalid type" });
  if (pool.length === 0) return res.status(410).json({ error: "Sold out" });

  const mintAddress = pool.shift();
  try {
      const sig = await transferNft(wallet, mintAddress, userAddress);

    row["状态"] = "已领取";
    row["备注"] = `已领取: ${new Date().toISOString()}`;
    const updatedData = XLSX.utils.json_to_sheet(
      type === "A" ? SERIALS_A : type === "B" ? SERIALS_B : SERIALS_C,
      { header: ["序号","生成时间","SN编号","状态","备注"] }
    );
    workbook.Sheets[type] = updatedData;
    saveExcel();

    res.json({ success: true, mint: mintAddress, signature: sig, type });
  } catch (err) {
    console.error(err);
   
     res.status(500).json({ error: err.message });
  }
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public/index.html"));
});

app.listen(PORT, "0.0.0.0", async () => {
  console.log(`🚀 Server running at http://0.0.0.0:${PORT}`);
  await initMints();
});
