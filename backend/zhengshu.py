from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timedelta
import os

def generate_ca_certificate():
    # 生成CA私钥
    ca_private_key = ec.generate_private_key(ec.SECP256R1())
    
    # 保存CA私钥
    with open("firmware_key.pem", "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # 构建CA证书
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UnionKey"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"NA"), 
        x509.NameAttribute(NameOID.COMMON_NAME, u"UNIONKEY_DEV_CA"),
    ])
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(ca_private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.utcnow())
    builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=3650))
    
    # 添加扩展
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,    # CA可以签发证书
            crl_sign=True,         # CA可以签发CRL
            encipher_only=False,
            decipher_only=False
        ), critical=True
    )
    
    # 自签名
    ca_certificate = builder.sign(
        private_key=ca_private_key,
        algorithm=hashes.SHA256()
    )
    
    # 保存CA证书
    with open("firmware_ca.pem", "wb") as f:
        f.write(ca_certificate.public_bytes(serialization.Encoding.PEM))
    
    print("✅ CA私钥已生成: firmware_key.pem")
    print("✅ CA证书已生成: firmware_ca.pem")
    
    # 也导出公钥（用于兼容旧的验证方式）
    with open("firmware_key_pub.pem", "wb") as f:
        f.write(ca_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("✅ CA公钥已生成: firmware_key_pub.pem")

if __name__ == "__main__":
    generate_ca_certificate()