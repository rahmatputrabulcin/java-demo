package com.paytend.api.utils;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.lang.UUID;
import cn.hutool.json.JSONUtil;
import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.net.URLDecoder;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * @author wanghuaiqing
 * @description RSA加解密类
 * @date 2023/8/23 16:41
 */
public class RSAUtils {

    private static final Log log = LogFactory.get();

    /**
     * 默认编码格式
     */
    private static final String DEFAULT_CHARSET = "UTF-8";

    /**
     * 加密算法RSA
     */
    public static final String KEY_ALGORITHM = "RSA";

    /**
     * 签名算法
     */
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";
    public static final String SIGNATURE_ALGORITHM_SHA256 = "SHA256withRSA";

    /**
     * 获取公钥的key
     */
    private static final String PUBLIC_KEY = "RSAPublicKey";

    /**
     * 获取私钥的key
     */
    private static final String PRIVATE_KEY = "RSAPrivateKey";

    /**
     * RSA最大加密明文大小
     */
    private static final int MAX_ENCRYPT_BLOCK = 117;

    /**
     * RSA最大解密密文大小
     */
    private static final int MAX_DECRYPT_BLOCK = 128;

    /**
     * encode byte[]
     */
    public static String encode(byte[] bytes) {
        return new String(Base64.encode(bytes));
    }

    /**
     * decode字符串
     */
    public static byte[] decode(String base64) {
        return Base64.decode(base64);
    }


    /**
     * 生成密钥对(公钥和私钥)
     *
     * @return
     * @throws Exception
     */
    public static Map<String, Object> genKeyPair(int keySize) throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(keySize);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        Map<String, Object> keyMap = new HashMap<String, Object>(2);
        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
    }

    /**
     * 用私钥对信息生成数字签名
     *
     * @param data       已加密数据
     * @param privateKey 私钥(BASE64编码)
     * @throws Exception
     */
    public static String signSHA256(byte[] data, String privateKey) throws Exception {
        byte[] keyBytes = decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM_SHA256);
        signature.initSign(privateK);
        signature.update(data);
        return encode(signature.sign());
    }

    /**
     * 校验数字签名
     *
     * @param data      已加密数据
     * @param publicKey 公钥(BASE64编码)
     * @param sign      数字签名
     * @throws Exception
     */
    public static boolean verifySHA256(byte[] data, String publicKey, String sign) throws Exception {
        byte[] keyBytes = decode(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicK = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM_SHA256);
        signature.initVerify(publicK);
        signature.update(data);
        return signature.verify(decode(sign));
    }

    /**
     * 用私钥对信息生成数字签名
     *
     * @param data       已加密数据
     * @param privateKey 私钥(BASE64编码)
     * @throws Exception
     */
    public static String sign(byte[] data, String privateKey) throws Exception {
        byte[] keyBytes = decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateK);
        signature.update(data);
        return encode(signature.sign());
    }

    /**
     * 校验数字签名
     *
     * @param data      已加密数据
     * @param publicKey 公钥(BASE64编码)
     * @param sign      数字签名
     * @throws Exception
     */
    public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {
        byte[] keyBytes = decode(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicK = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicK);
        signature.update(data);
        return signature.verify(decode(sign));
    }

    /**
     * 私钥解密
     *
     * @param encryptedData 已加密数据
     * @param privateKey    私钥(BASE64编码)
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey) throws Exception {
        byte[] keyBytes = decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateK);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    /**
     * 公钥解密
     *
     * @param encryptedData 已加密数据
     * @param publicKey     公钥(BASE64编码)
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] encryptedData, String publicKey) throws Exception {
        byte[] keyBytes = decode(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicK);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    /**
     * 公钥加密
     *
     * @param data      源数据
     * @param publicKey 公钥(BASE64编码)
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data, String publicKey) throws Exception {
        byte[] keyBytes = decode(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicK);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }


    /**
     * 私钥加密
     *
     * @param data       源数据
     * @param privateKey 私钥(BASE64编码)
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] data, String privateKey) throws Exception {
        byte[] keyBytes = decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateK);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }

    /**
     * 获取私钥
     *
     * @param keyMap 密钥对
     * @throws Exception
     */
    public static String getPrivateKey(Map<String, Object> keyMap) throws Exception {
        Key key = (Key) keyMap.get(PRIVATE_KEY);
        return encode(key.getEncoded());
    }

    /**
     * 获取公钥
     *
     * @param keyMap 密钥对
     * @throws Exception
     */
    public static String getPublicKey(Map<String, Object> keyMap) throws Exception {
        Key key = (Key) keyMap.get(PUBLIC_KEY);
        return encode(key.getEncoded());
    }

    /**
     * 公钥加密
     *
     * @param data
     * @param PUBLICKEY
     * @return
     */
    public static String encryptPublicKey(String data, String PUBLICKEY) {
        try {
            data = encode(encryptByPublicKey(data.getBytes(DEFAULT_CHARSET), PUBLICKEY));
        } catch (Exception e) {
            e.printStackTrace();
            return data;
        }
        return data;
    }

    /**
     * 私钥解密
     *
     * @param data
     * @param privateKey
     * @return
     */
    public static String decryptPrivateKey(String data, String privateKey) {
        String temp = "";
        try {
            if (data.contains("%")) {
                data = URLDecoder.decode(data, DEFAULT_CHARSET);
            }
            byte[] rs = decode(data);
            temp = new String(decryptByPrivateKey(rs, privateKey), DEFAULT_CHARSET);
        } catch (Exception e) {
            log.error("RSA Data decryption error", e);
        }
        return temp;
    }

    /**
     * 私钥加密
     * @param data
     * @param privateKey
     * @return
     */
    public static String encryptByPrivateKey(String data,String privateKey){
        try {
            return new String(encryptByPrivateKey(decode(data),privateKey),DEFAULT_CHARSET);
        } catch (Exception e) {
            log.error("RSA data encrypt error");
        }
        return "";
    }

    public static void main(String[] args) throws Exception {
        String secret = "8Z9CpC3y3OApAYJpLFxH1w==";
        String str = "qasRAL+JHRtO2hNDvcDg9BlGENFHpz1RNl0Jq7M7aGTvSGIumq8vbX1NXD6JKivb4M4d5nKw+VSQOSwAxLHANxN+meFG/oizbMO9vYq4SaZbn09jZmrVtFXV3vMsb1eQLcqwPdT2A1wQXJa+CA46IVkBLJQKslzRYt4gg6e69Mw=";
        String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAN7ABtzTGVioQEztflR3gqe0MGNOPNuxcWDjZF9gIUS38MqQmW55+oDSJZWaY52cpiHtvsyHljeY9IJuo6wQGQweaOxP2pxUhVJ40OJZ3YOOf9YJlMcyPtquynYSSpeZIjmIYXG+r3yFDYhMyPfgy1OVrrYjm4kUprKIPW9korG5AgMBAAECgYAHVo4jUjUAjbJoll5WDAXa3n3Fl7s7hZH1nigdWD5gVCrzkWXslMoi2klwr0Be3d0/OuTROhpBxKExdtGfhnw8sTvEj+FxvhFyoCT7DbuZr81WKpI7ncCGafDDC142B+D4oWsP2XrGGqSfWbq9/DRRXBMFWPNSLCQMNagMiRWcnQJBAPD/5ZiAvc+WWttww5vT3+fCL83EuqSH02Tt2jAIvjiD73l7vuqpEdjFoq4RJXpeu5j86AJA/msPPLAXdEw0aPMCQQDsnVdjSCC9tSPFvLPSteBuiMT0gLOBuOfuEKoY46eQ4KFINGZIvvdexCmjr+lKhgUljqhPCzOTJ7j98U+9tGWjAkA4T4KFFKfFJluKZJnAAkyR6WSkDrCRmw8AyTau/Iv9xo4g85ITYHfED8HILEd2hUYOJCHNzQPlXgUPHBvXZnOTAkEAsV8hayNep9dqAYj7pDEDFNkiC8eOyOe7tRJ48D94FXrObDobktzUww15yWLNFzhwEz9lnBthhiZ43qROin740QJASqiQ5egVBSkGk7IUrISUtz/FFY+ZjBi63fr+LLSu5INOJx/qNaAh6iQQ7+5hZr8QXLOgxx2cE9IES3cGbfICwQ==";
        String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDKaMyoBXfk65i3fI70y+Hod18my5v4tFlsClrS5Jyx+gR5FuA4kmug+CbuVbiwaqB8UiP2cXG9xsl9lu/e0E0Scp1ITgosHurpGPfsKL3Bk+C74KkEsUfo4tp+lbpwPDovGEyhEviGUB3r6qcoez6L63b3JDgCyQh5HBNG7z+mgwIDAQAB";
        String PAYTEND_PUBLICKEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDewAbc0xlYqEBM7X5Ud4KntDBjTjzbsXFg42RfYCFEt/DKkJluefqA0iWVmmOdnKYh7b7Mh5Y3mPSCbqOsEBkMHmjsT9qcVIVSeNDiWd2Djn/WCZTHMj7arsp2EkqXmSI5iGFxvq98hQ2ITMj34MtTla62I5uJFKayiD1vZKKxuQIDAQAB";
//        System.out.println(decryptPrivateKey(str, privateKey));
//        System.out.println(encryptPublicKey("123456",PAYTEND_PUBLICKEY));
//        String str = encryptPublicKey("123456",PAYTEND_PUBLICKEY);
//        System.out.println(decryptPrivateKey(str,privateKey));
        String aesKey = AESUtils.generateKey();
        Map map = new HashMap();

        Map bizData = new HashMap();
        bizData.put("randomStr", UUID.randomUUID());

        map.put("agentId","888666000100201");
        map.put("language","zh");
        map.put("randomKey",encryptPublicKey(aesKey,PAYTEND_PUBLICKEY));
        map.put("bizData",AESUtils.encrypt(JSONUtil.toJsonStr(bizData),aesKey));
        map.put("signature","");
        map.put("version","");



        System.out.println("request:" + JSONUtil.toJsonStr(map));

    }
}
