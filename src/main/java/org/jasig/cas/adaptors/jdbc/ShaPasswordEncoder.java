package org.jasig.cas.adaptors.jdbc;


import lombok.Data;
import org.apache.shiro.crypto.RandomNumberGenerator;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.util.ByteSource;

@Data
public class ShaPasswordEncoder {

    private RandomNumberGenerator randomNumberGenerator = null;

    private String algorithmName = "sha";

    private int hashIterations = 2;

    public ShaPasswordEncoder() {
        randomNumberGenerator = new SecureRandomNumberGenerator();
    }

    public String encrypt(String value, String salt) {
        return new SimpleHash(algorithmName, value, ByteSource.Util.bytes(salt), hashIterations).toHex();
    }

}