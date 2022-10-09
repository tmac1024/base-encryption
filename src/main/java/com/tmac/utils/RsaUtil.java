package com.tmac.utils;

import com.tmac.constant.RsaConstants;
import org.apache.tomcat.util.codec.binary.Base64;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.net.URLDecoder;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class RsaUtil {

    /**
     * 生成密钥对(公钥和私钥)
     *
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static Map<String, Object> genKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(RsaConstants.KEY_ALGORITHM);
        keyPairGen.initialize(RsaConstants.INITIALIZE_LENGTH);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        String publicKeyString = new String(Base64.encodeBase64(publicKey.getEncoded()));
        String privateKeyString = new String(Base64.encodeBase64(privateKey.getEncoded()));
        Map<String, Object> keyMap = new HashMap<String, Object>(2);
        keyMap.put(RsaConstants.PUBLIC_KEY, publicKeyString);
        keyMap.put(RsaConstants.PRIVATE_KEY, privateKeyString);
        return keyMap;
    }

    /**
     * 用私钥对信息生成数字签名
     *
     * @param data       已加密数据
     * @param privateKey 私钥(BASE64编码)
     * @return 获取签名
     * @throws Exception
     */
    public static String sign(byte[] data, String privateKey) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RsaConstants.KEY_ALGORITHM);
        PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Signature signature = Signature.getInstance(RsaConstants.SIGNATURE_ALGORITHM);
        signature.initSign(privateK);
        signature.update(data);
        return Base64.encodeBase64String(signature.sign());
    }


    /**
     * 校验数字签名
     *
     * @param data      已加密数据
     * @param publicKey 公钥(BASE64编码)
     * @param sign      数字签名
     * @return 验证通过返回true
     * @throws Exception
     */
    public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RsaConstants.KEY_ALGORITHM);
        PublicKey publicK = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance(RsaConstants.SIGNATURE_ALGORITHM);
        signature.initVerify(publicK);
        signature.update(data);
        return signature.verify(Base64.decodeBase64(sign));
    }

    /**
     * 私钥解密
     *
     * @param encryptedData 已加密数据
     * @param privateKey    私钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static String decryptByPrivateKey(byte[] encryptedData, String privateKey) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RsaConstants.KEY_ALGORITHM);
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
            if (inputLen - offSet > RsaConstants.MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, RsaConstants.MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * RsaConstants.MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return new String(decryptedData, "UTF-8");
    }

    /**
     * 公钥解密
     *
     * @param encryptedData 已加密数据
     * @param publicKey     公钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPublicKey(byte[] encryptedData, String publicKey) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RsaConstants.KEY_ALGORITHM);
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
            if (inputLen - offSet > RsaConstants.MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(encryptedData, offSet, RsaConstants.MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * RsaConstants.MAX_DECRYPT_BLOCK;
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
     * @return
     * @throws Exception
     */
    public static String encryptByPublicKey(byte[] data, String publicKey) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RsaConstants.KEY_ALGORITHM);
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
            if (inputLen - offSet > RsaConstants.MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, RsaConstants.MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * RsaConstants.MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return Base64.encodeBase64String(encryptedData);
    }

    /**
     * 私钥加密
     *
     * @param data       源数据
     * @param privateKey 私钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPrivateKey(byte[] data, String privateKey) throws Exception {
        byte[] keyBytes = Base64.decodeBase64(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RsaConstants.KEY_ALGORITHM);
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
            if (inputLen - offSet > RsaConstants.MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data, offSet, RsaConstants.MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * RsaConstants.MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }

    /**
     * 获取私钥
     *
     * @param keyMap 密钥对
     * @return
     * @throws Exception
     */
    public static String getPrivateKey(Map<String, Object> keyMap) throws Exception {
        Key key = (Key) keyMap.get(RsaConstants.PRIVATE_KEY);
        return Base64.encodeBase64String(key.getEncoded());
    }

    /**
     * 获取公钥
     *
     * @param keyMap 密钥对
     * @return
     * @throws Exception
     */
    public static String getPublicKey(Map<String, Object> keyMap) throws Exception {
        Key key = (Key) keyMap.get(RsaConstants.PUBLIC_KEY);
        return Base64.encodeBase64String(key.getEncoded());
    }

    /**
     * java端公钥加密
     *
     * @param data
     * @param publicKey
     * @return
     */
    public static Object encryptedDataOnJava(Object data, String publicKey) {

        byte[] bytes = null;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(data);
            oos.flush();
            bytes = bos.toByteArray();
            oos.close();
            bos.close();
            data = encryptByPublicKey(bytes, publicKey);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return data;
    }

    /**
     * java端私钥解密
     *
     * @param data
     * @param privateKey
     * @return
     */
    public static String decryptDataOnJava(String data, String privateKey) {
        String temp = "";
        try {
            byte[] rs = Base64.decodeBase64(data);
            temp = RsaUtil.decryptByPrivateKey(rs, privateKey);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return temp;
    }


    public static void main(String[] args) throws NoSuchAlgorithmException {
//        Map<String, Object> stringObjectMap = genKeyPair();
//        System.out.println("公钥" + stringObjectMap.get(RsaConstants.PUBLIC_KEY));
//        System.out.println("私钥" + stringObjectMap.get(RsaConstants.PRIVATE_KEY));

        //1
        String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCS4ZoU2JY1UP76XCeEc/p6TBNzqKlrJH9EwCmtvjnJcD6lf3Z+O1BWTjRy4+TEOdlqMxoHgrdAM3qzFp7lXvAiGksfU1mrxv28Luv6wj1pEDNsclUqbr3RPdcQHLtjph1kxWvE1LGJlVYPNaUfOy40qwxehWMHjkQNewztBpuI+wIDAQAB";
        String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJLhmhTYljVQ/vpcJ4Rz+npME3OoqWskf0TAKa2+OclwPqV/dn47UFZONHLj5MQ52WozGgeCt0AzerMWnuVe8CIaSx9TWavG/bwu6/rCPWkQM2xyVSpuvdE91xAcu2OmHWTFa8TUsYmVVg81pR87LjSrDF6FYweORA17DO0Gm4j7AgMBAAECgYAubJPwxswjKeiNZRcwbB/dC7KSOdrifHSlXD9QJPHK02lZkcH3//NSdAFr1s/1nXs0b9ZoTU5yQlMjy6CJSsqG35TEkBROYJkmwht8AJyvMqgIr5cOib4elzRBmid60cxOEUAAghS9W/LMarg6caHBmuBTNUvbToOlIjSavRBRYQJBAO8ea6J4djp4SD3RH3WWxhmoKnNVMFeK0lCYA9o+7jRYY5APIHy5fFmvIy7vr2kuu/IOSci/KHgmmOtMubfUk9MCQQCdQC12yFzDuLNNWRHGmVdC4aEQhyGOAiypohsidqmufJvMNmHT3N6IcpcglH+kK0fSzGweQuvvWJvdRLMgXoU5AkBgt6E5mhfYFobB2jArU8zU29wvwilHf3MJ/jKwt/uJWKcMwdGWIUBW1iwY9AGzPZ/vjC/z7r3ju1jm86W64VTZAkBBsPfNMXKfSN+OpnDomFJ93Cge8XSxEHN8Af537T6BaAjlzKodiZ1lPwmnUKHqATKl+0QHeEl72XZzfymdkh7xAkEAxM2JSnHDmwyKLNhPs9qujV/oR1yKZHxgxV3Vwa189bIG2vZWWtNqQqa9fb0daUd+zB70z1eS028dLc8iOP2asA==";
        //2
//        String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+CHgKtBp6OBK8Mhy5nSog6VxrOeZMqvlxJuX0tb8z3MK6v8NAQyH6KCeln3Wh6Z3wdrvpOBbqCtt/ps0wXKE6eJdNaRZ3XL2UDDG8M/ED5FQ32LnR4qXW8bCEP4iF26fVusMFHcnIc3Mla9MmK1zODkGDJcIbpDHWP+S783LTYwIDAQAB";
//        String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAL4IeAq0Gno4ErwyHLmdKiDpXGs55kyq+XEm5fS1vzPcwrq/w0BDIfooJ6WfdaHpnfB2u+k4FuoK23+mzTBcoTp4l01pFndcvZQMMbwz8QPkVDfYudHipdbxsIQ/iIXbp9W6wwUdychzcyVr0yYrXM4OQYMlwhukMdY/5LvzctNjAgMBAAECgYAar2/D+QSa0xL2cIcOHZ7T3lFHEWtgqsW6eP7jvT3rV33U4abWeFbmHQtsO5c2NGskYFgE6QZ2uS2XoGHB/8/3+sn9kzZ9aciSsU1keOmlCIySZ+ZSE6IWo5y/PwP1V5/AHPMdzIQmtwInIZDhiEBAtdyAB4x5KOKHFhbnqp+zkQJBAPLDbR3NyqR2QO14WJqcx7iddc+R4x2omZlpiujX7BhdXE1/uJMsD+nYK8uteA0SrUB+kiEsVuP2vhWWuZ6YnfkCQQDIZQPk6luKzFUZNstgMIwciWrfNy1UzHDl6Sav3ZIf8mKY7eFC7ttN6ep5HpylQ4I+W+Hpcw+f1Sx0WpbU8IM7AkEA2GpPhBpJZIPnLcvzcSIDChmVRQ4RIgeDprfoFdsnpjDUcGJD8S9+oEEOCe0C8OSNfslXDCuy6la07hoIL9JuQQJASxz6AbMKjxMaDrJoNuzbh9LGWVbAShm7c6IZ2y+tFwZuiK4ZklIfp6u3NKERzCxqxF8CZdO4Fov79r0B7l0cgwJAbefHpEi/hW+6JTy9V8vafp1T3W/NGGDy5pno1XqrivgJ3XiLRkMgYHYBLlQz8T4t7q65TVa8PFukM1GvjeTWDA==";
//                String message = "{\"msg\":\"获取登录用户信息成功\",\"code\":200,\"data\":{\"cardType\":\"1\",\"cardNo\":\"12010319881104142X\",\"stuName\":\"韩雪 \",\"phone\":\"18622198800\",\"age\":33,\"sex\":\"1\",\"firstCardDate\":null,\"certRenewalDate\":null,\"certBeginDate\":null,\"certEndDate\":null,\"certReviewDate\":null,\"address\":\"天津市市辖区河西区\",\"highestEducation\":\"本科或同等学历\",\"rsaPublicKey\":null,\"rsaPrivateKey\":null}}";
                        int message = 1;
        try {
            String str1 = encryptByPublicKey(String.valueOf(message).getBytes(), publicKey);
            System.out.println("加密后:" + str1);
            System.out.println("str1:" + str1.length());
            String str = "c+F3ZAW0VHPu6772vJrXzGfOTkTDyxWopjW4oRziO7vqg027dlHxCMJmfoaD0DpoDuA28bzuURHaZDhjKkFkd9pNZEe7E7jcOrQ2QlSgk/k4Wd/I/uaBATkFn2aGO0Ls9y2AZYPzYNvoBmpiAls6XjnTYlB6KIThryHitRkTowo=";
            //            System.out.println("str:" + str1.length());
//            String s = new String(Base64.encodeBase64(str1.getBytes()));
            byte[] bytes1 = Base64.decodeBase64(str);
//            URLDecoder.decode(new String(bytes1), "utf-8");
            String s1 = decryptByPrivateKey(bytes1, privateKey);
            System.out.println("解密后:" + s1);
            String decode = URLDecoder.decode(s1);
            System.out.println("decode::" + decode);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
