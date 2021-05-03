package com.chengzw.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Map;
import java.util.UUID;

/**
 * JWT服务类，对JwtUtils进行二次封装，提供加密和解密的方法
 * @author 程治玮
 * @since 2021/5/3 10:43 上午
 */
public class JwtService {

    /**
     * token 过期时间, 单位: 秒. 这个值表示 30 天
     */
    private static final long TOKEN_EXPIRED_TIME = 30 * 24 * 60 * 60;

    /**
     * jwt 加密解密密钥
     */

    //签名密钥算法
    private static SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
    //生成签名密钥
    //方式一：自己定义加密解密密钥
    //private static String JWT_SECRET = "MDk4ZjZiY2Q0NjIxZDM3M2NhZGU0ZTgzMjYyN2I0ZjY=";
    //private static byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(JWT_SECRET);
    //private static Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

    //方式二：传入签名算法，自动生成密钥
    private static Key signingKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);


    /**
     * 个人签名
     */
    private static final String JWT_ISSUER = "CZW";

    /**
     * 描述:创建令牌
     *
     * @param map      主题，也差不多是个人的一些信息，为了好的移植，采用了map放个人信息，而没有采用JSON
     * @param audience 发送谁
     * @return java.lang.String
     */
    public static String createPersonToken(Map map, String audience) {
        String personToken = JwtUtils.createJWT(map, audience, UUID.randomUUID().toString(), JWT_ISSUER, TOKEN_EXPIRED_TIME, signingKey, signatureAlgorithm);
        return personToken;
    }


    /**
     * 描述:解密JWT
     *
     * @param personToken JWT字符串,也就是token字符串
     * @return io.jsonwebtoken.Claims
     */
    public static Claims parsePersonJWT(String personToken) {
        Claims claims = JwtUtils.parseJWT(personToken, signingKey);
        return claims;
    }
}