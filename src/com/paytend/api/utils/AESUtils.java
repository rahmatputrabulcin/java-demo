package com.paytend.api.utils;


import cn.hutool.core.codec.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * @author wanghuaiqing
 * @description TODO
 * @date 2023/8/23 11:06
 */
public class AESUtils {

    /**
     * 加密算法AES
     */
    private static final String KEY_ALGORITHM = "AES";

    /**
     * 算法名称/加密模式/数据填充方式 默认：AES/ECB/PKCS5Padding
     */
    private static final String ALGORITHMS = "AES/ECB/PKCS5Padding";

    /**
     * 生成密钥的长度，可以修改为128, 192或256
     */
    private static final int KEY_LENGTH = 128;

    /**
     * 加密
     *
     * @param content 加密的字符串
     * @param encryptKey key值
     */
    public static String encrypt(String content, String encryptKey) throws Exception {
        // 设置Cipher对象
        Cipher cipher = Cipher.getInstance(ALGORITHMS);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encryptKey.getBytes(), KEY_ALGORITHM));

        // 调用doFinal
        byte[] b = cipher.doFinal(content.getBytes(StandardCharsets.UTF_8));

        // 转base64
        return Base64.encode(b);
    }

    /**
     * 解密
     *
     * @param encryptStr 解密的字符串
     * @param decryptKey 解密的key值
     */
    public static String decrypt(String encryptStr, String decryptKey) throws Exception {
        // base64格式的key字符串转byte
        byte[] decodeBase64 = Base64.decode(encryptStr);
        // 设置Cipher对象
        Cipher cipher = Cipher.getInstance(ALGORITHMS);

        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptKey.getBytes(StandardCharsets.UTF_8), KEY_ALGORITHM));

        // 调用doFinal解密
        byte[] decryptBytes = cipher.doFinal(decodeBase64);
        return new String(decryptBytes);
    }

    /**
     * 生成AES 密钥
     *
     * @return
     * @throws Exception
     */
    public static String generateKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(KEY_ALGORITHM);
        // 下面调用方法的参数决定了生成密钥的长度，可以修改为128, 192或256
        kg.init(KEY_LENGTH);
        SecretKey sk = kg.generateKey();
        byte[] b = sk.getEncoded();
        String secret = Base64.encode(b);
        return secret;
    }

    public static void main(String[] args) throws Exception {
        String secret = "ebwjkuiwHhe0XhLK9NG62g==";
        String str = "xlyjHTeAx2/EpEvpzVvWQFqQOSVPGv6KKhUAbIQXdIE3B0EtnJgMe5IwYtLj5XHHaNx9JonfcypSpANGZVGLXg==";
        String encrypt = decrypt(str, secret);
        System.out.println("encrypt:" + encrypt);
        // String decrypt = decrypt(encrypt, "w5wUh1WGkEflSpkRuH699Q==");
        // System.out.println("decrypt" + decrypt);
    }
}
