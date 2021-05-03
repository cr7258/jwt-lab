package com.chengzw.util;

import io.jsonwebtoken.*;
import java.security.Key;
import java.util.Date;
import java.util.Map;

/**
 * JWT基础工具类
 * @author 程治玮
 * @since 2021/5/3 10:43 上午
 */
public class JwtUtils {


    /**
     * jwt解密，需要密钥和token，如果解密失败，说明token无效
     * @param jsonWebToken
     * @param signingKey
     * @return
     */
    public static Claims parseJWT(String jsonWebToken, Key signingKey) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(signingKey)
                    .parseClaimsJws(jsonWebToken)
                    .getBody();
            return claims;
        } catch (JwtException ex) {
            return null;
        }
    }

    /**
     * 创建token
     * jwt = 头部（至少指定算法） + 身体（JWT编码的所有声明） + 签名（将标题和正文的组合通过标题中指定的算法计算得出）
     * jws:JWT可以加密签名成为jws
     * @param map 主题，也差不多是个人的一些信息，为了好的移植，采用了map放个人信息，而没有采用JSON
     * @param audience 发送谁
     * @param issuer 个人签名
     * @param jwtId 相当于jwt的主键,不能重复
     * @param TTLMillis Token过期时间
     * @param signingKey 生成签名密钥
     * @return
     */
    public static String createJWT(Map map, String audience, String issuer, String jwtId, long TTLMillis, Key signingKey,SignatureAlgorithm signatureAlgorithm) {

        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);

        //添加构成JWT的参数
        JwtBuilder builder = Jwts.builder().setHeaderParam("typ", "JWT")
                .setIssuedAt(now)
                .setSubject(map.toString())
                .setIssuer(issuer)
                .setId(jwtId)
                .setAudience(audience)
                .signWith(signingKey, signatureAlgorithm);  //设置签名使用的签名算法和签名使用的秘钥
        //添加Token过期时间
        if (TTLMillis >= 0) {
            // 过期时间
            long expMillis = nowMillis + TTLMillis;
            // 现在是什么时间
            Date exp = new Date(expMillis);
            // 系统时间之前的token都是不可以被承认的
            builder.setExpiration(exp).setNotBefore(now);
        }
        //生成JWS（加密后的JWT）
        return builder.compact();
    }
}