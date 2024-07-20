package com.example.deploy.config;

import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class JasyptConfigTest {
    @Test
    @DisplayName("properties 암호화 테스트")
    public void jasyptEncryptorPassword() {
        String key = "kimdozzi";

        PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
        encryptor.setPoolSize(8);
        encryptor.setPassword(key);
        encryptor.setAlgorithm("PBEWithMD5AndTripleDES");

        String str = "{value}";
        String encryptStr = encryptor.encrypt(str);
        String decryptStr = encryptor.decrypt(encryptStr);

        System.out.println("ENC : " + encryptStr);
        System.out.println("DEC : " + decryptStr);
    }
}
