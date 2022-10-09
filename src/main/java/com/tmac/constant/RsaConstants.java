package com.tmac.constant;

public class RsaConstants {

    /** */
    /**
     * 加密算法RSA
     */
    public static final String KEY_ALGORITHM = "RSA";

    /** */
    /**
     * 签名算法
     */
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    /** */
    /**
     * 获取公钥的key
     */
    public static final String PUBLIC_KEY = "publicKey";

    /** */
    /**
     * 获取私钥的key
     */
    public static final String PRIVATE_KEY = "privateKey";

    /** */
    /**
     * RSA最大加密明文大小
     */
    public static final int MAX_ENCRYPT_BLOCK = 117;

    /** */
    /**
     * RSA最大解密密文大小
     */
    public static final int MAX_DECRYPT_BLOCK = 128;

    /** */
    /**
     * RSA 位数 如果采用2048 上面最大加密和最大解密则须填写:  245 256
     */
    public static final int INITIALIZE_LENGTH = 1024;

    /**
     *
     */
    public static final String ALGORITHMSTR = "AES/ECB/PKCS5Padding";


    /**
     * 登录接口公钥
     */
    public static final String LOGIN_PUBLICKEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCS4ZoU2JY1UP76XCeEc/p6TBNzqKlrJH9EwCmtvjnJcD6lf3Z+O1BWTjRy4+TEOdlqMxoHgrdAM3qzFp7lXvAiGksfU1mrxv28Luv6wj1pEDNsclUqbr3RPdcQHLtjph1kxWvE1LGJlVYPNaUfOy40qwxehWMHjkQNewztBpuI+wIDAQAB";
    //对应私钥MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJLhmhTYljVQ/vpcJ4Rz+npME3OoqWskf0TAKa2+OclwPqV/dn47UFZONHLj5MQ52WozGgeCt0AzerMWnuVe8CIaSx9TWavG/bwu6/rCPWkQM2xyVSpuvdE91xAcu2OmHWTFa8TUsYmVVg81pR87LjSrDF6FYweORA17DO0Gm4j7AgMBAAECgYAubJPwxswjKeiNZRcwbB/dC7KSOdrifHSlXD9QJPHK02lZkcH3//NSdAFr1s/1nXs0b9ZoTU5yQlMjy6CJSsqG35TEkBROYJkmwht8AJyvMqgIr5cOib4elzRBmid60cxOEUAAghS9W/LMarg6caHBmuBTNUvbToOlIjSavRBRYQJBAO8ea6J4djp4SD3RH3WWxhmoKnNVMFeK0lCYA9o+7jRYY5APIHy5fFmvIy7vr2kuu/IOSci/KHgmmOtMubfUk9MCQQCdQC12yFzDuLNNWRHGmVdC4aEQhyGOAiypohsidqmufJvMNmHT3N6IcpcglH+kK0fSzGweQuvvWJvdRLMgXoU5AkBgt6E5mhfYFobB2jArU8zU29wvwilHf3MJ/jKwt/uJWKcMwdGWIUBW1iwY9AGzPZ/vjC/z7r3ju1jm86W64VTZAkBBsPfNMXKfSN+OpnDomFJ93Cge8XSxEHN8Af537T6BaAjlzKodiZ1lPwmnUKHqATKl+0QHeEl72XZzfymdkh7xAkEAxM2JSnHDmwyKLNhPs9qujV/oR1yKZHxgxV3Vwa189bIG2vZWWtNqQqa9fb0daUd+zB70z1eS028dLc8iOP2asA==


    /**
     * 登录接口私钥
     */
    public static final String LOGIN_PRIVATEKEY = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAL4IeAq0Gno4ErwyHLmdKiDpXGs55kyq+XEm5fS1vzPcwrq/w0BDIfooJ6WfdaHpnfB2u+k4FuoK23+mzTBcoTp4l01pFndcvZQMMbwz8QPkVDfYudHipdbxsIQ/iIXbp9W6wwUdychzcyVr0yYrXM4OQYMlwhukMdY/5LvzctNjAgMBAAECgYAar2/D+QSa0xL2cIcOHZ7T3lFHEWtgqsW6eP7jvT3rV33U4abWeFbmHQtsO5c2NGskYFgE6QZ2uS2XoGHB/8/3+sn9kzZ9aciSsU1keOmlCIySZ+ZSE6IWo5y/PwP1V5/AHPMdzIQmtwInIZDhiEBAtdyAB4x5KOKHFhbnqp+zkQJBAPLDbR3NyqR2QO14WJqcx7iddc+R4x2omZlpiujX7BhdXE1/uJMsD+nYK8uteA0SrUB+kiEsVuP2vhWWuZ6YnfkCQQDIZQPk6luKzFUZNstgMIwciWrfNy1UzHDl6Sav3ZIf8mKY7eFC7ttN6ep5HpylQ4I+W+Hpcw+f1Sx0WpbU8IM7AkEA2GpPhBpJZIPnLcvzcSIDChmVRQ4RIgeDprfoFdsnpjDUcGJD8S9+oEEOCe0C8OSNfslXDCuy6la07hoIL9JuQQJASxz6AbMKjxMaDrJoNuzbh9LGWVbAShm7c6IZ2y+tFwZuiK4ZklIfp6u3NKERzCxqxF8CZdO4Fov79r0B7l0cgwJAbefHpEi/hW+6JTy9V8vafp1T3W/NGGDy5pno1XqrivgJ3XiLRkMgYHYBLlQz8T4t7q65TVa8PFukM1GvjeTWDA==";
    //对应公钥MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+CHgKtBp6OBK8Mhy5nSog6VxrOeZMqvlxJuX0tb8z3MK6v8NAQyH6KCeln3Wh6Z3wdrvpOBbqCtt/ps0wXKE6eJdNaRZ3XL2UDDG8M/ED5FQ32LnR4qXW8bCEP4iF26fVusMFHcnIc3Mla9MmK1zODkGDJcIbpDHWP+S783LTYwIDAQAB

}
