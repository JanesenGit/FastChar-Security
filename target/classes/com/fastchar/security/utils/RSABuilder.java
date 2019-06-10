package com.fastchar.security.utils;

import com.fastchar.core.FastChar;
import com.fastchar.utils.FastFileUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import java.io.File;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class RSABuilder {

    private int keyLength = 1024;
    private String privateKeyPkcs8File;
    private String privateKeyFile;
    private String publicKeyFile;

    public int getKeyLength() {
        return keyLength;
    }

    public RSABuilder setKeyLength(int keyLength) {
        this.keyLength = keyLength;
        return this;
    }

    public String getPrivateKeyPkcs8File() {
        return privateKeyPkcs8File;
    }

    public RSABuilder setPrivateKeyPkcs8File(String privateKeyPkcs8File) {
        this.privateKeyPkcs8File = privateKeyPkcs8File;
        return this;
    }

    public String getPrivateKeyFile() {
        return privateKeyFile;
    }

    public RSABuilder setPrivateKeyFile(String privateKeyFile) {
        this.privateKeyFile = privateKeyFile;
        return this;
    }

    public String getPublicKeyFile() {
        return publicKeyFile;
    }

    public RSABuilder setPublicKeyFile(String publicKeyFile) {
        this.publicKeyFile = publicKeyFile;
        return this;
    }

    public void builder() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keyLength);
            KeyPair keyPair = kpg.generateKeyPair();

            File privateKeyPkcs8 = new File(privateKeyPkcs8File);
            FastFileUtils.writeStringToFile(privateKeyPkcs8, pkcsToPem(keyPair.getPrivate().getEncoded(), false));

            File privateKey = new File(privateKeyFile);
            FastFileUtils.writeStringToFile(privateKey, toPkcs1Pem(keyPair.getPrivate().getEncoded()));

            File publicKey = new File(publicKeyFile);
            FastFileUtils.writeStringToFile(publicKey, pkcsToPem(keyPair.getPublic().getEncoded(), true));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    private String pkcsToPem(byte[] keyBytes, boolean isPublic) throws Exception {
        String type;
        if (isPublic) {
            type = "RSA PUBLIC KEY";
        } else {
            type = "RSA PRIVATE KEY";
        }
        PemObject pemObject = new PemObject(type, keyBytes);
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        return stringWriter.toString();
    }


    private String toPkcs1Pem(byte[] privateBytes) throws Exception {
        PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privateBytes);
        ASN1Encodable asn1Encodable = pkInfo.parsePrivateKey();
        ASN1Primitive asn1Primitive = asn1Encodable.toASN1Primitive();
        byte[] privateKeyPKCS1 = asn1Primitive.getEncoded();
        return pkcsToPem(privateKeyPKCS1, false);
    }

}
