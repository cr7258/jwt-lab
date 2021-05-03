# JWT（JSON Web Token）

## 常见的认证方式
### HTTP Basic Auth
HTTP Basic Auth 一种最古老的安全认证方式，这种方式就是简单的访问API的时候，带上访问的username和password，由于信息会暴露出去，所以现在也越来越少用了。
### Cookie + Session
服务端验证后，创建一个 Session 信息，服务端存储 Session信息，并且将 SessionID 存到 cookie，发送回浏览器。下次客户端再发起请求，自动带上 cookie 信息，服务端通过 cookie 的 SessionID 获取 Session 信息进行校验。
### Token
基于 token 的鉴权机制类似于 HTTP 协议也是无状态的，它不需要在服务端去保留用户的认证信息或者会话信息。第一次登陆成功后，服务端返回给客户端一个 token 值，客户端存储token，并在每次请求时附送上这个 token 值，服务端通过解析 token 的值判断用户的合法性。
### JWT
JWT 是 token 的一种优化，把数据直接放在 token 中，然后对 token 加密，服务端获取token后，解密就可以获取客户端信息，不需要再去数据库查询客户端信息了。

## 什么是 Cookie
HTTP 是无状态的协议（对于事务处理没有记忆能力，每次客户端和服务端会话完成时，服务端不会保存任何会话信息）：每个请求都是完全独立的，服务端无法确认当前访问者的身份信息，无法分辨上一次的请求发送者和这一次的发送者是不是同一个人。所以服务器与浏览器为了进行会话跟踪（知道是谁在访问我），就必须主动的去维护一个状态，这个状态用于告知服务端前后两个请求是否来自同一浏览器。而这个状态需要通过 cookie 或者 session 去实现。

cookie 存储在客户端： cookie 是服务器发送到用户浏览器并保存在本地的一小块数据，它会在浏览器下次向同一服务器再发起请求时被携带并发送到服务器上。

cookie 是不可跨域的： 每个 cookie 都会绑定单一的域名，无法在别的域名下获取使用，一级域名和二级域名之间是允许共享使用的（靠的是 domain）。

## 什么是 Session
session 是另一种记录服务器和客户端会话状态的机制。
session 是基于 cookie 实现的，session 存储在服务器端，sessionId 会被存储到客户端的cookie 中。

![](https://chengzw258.oss-cn-beijing.aliyuncs.com/Article/20210502224357.png)

session 认证流程：
* 用户第一次请求服务器的时候，服务器根据用户提交的相关信息，创建对应的 Session。
* 请求返回时将此 Session 的唯一标识信息 SessionID 返回给浏览器。
* 浏览器接收到服务器返回的 SessionID 信息后，会将此信息存入到 Cookie 中，同时 Cookie 记录此 SessionID 属于哪个域名。
* 当用户第二次访问服务器的时候，请求会自动判断此域名下是否存在 Cookie 信息，如果存在自动将 Cookie 信息也发送给服务端，服务端会从 Cookie 中获取 SessionID，再根据 SessionID 查找对应的 Session 信息，如果没有找到说明用户没有登录或者登录失效，如果找到 Session 证明用户已经登录可执行后面操作。

根据以上流程可知，SessionID 是连接 Cookie 和 Session 的一道桥梁，大部分系统也是根据此原理来验证用户登录状态。

## Cookie 和 Session 的区别
* 安全性： Session 比 Cookie 安全，Session 是存储在服务器端的，Cookie 是存储在客户端的。
* 存取值的类型不同：Cookie 只支持存字符串数据，想要设置其他类型的数据，需要将其转换成字符串，Session 可以存任意数据类型。
* 有效期不同： Cookie 可设置为长时间保持，比如我们经常使用的默认登录功能，Session 一般失效时间较短，客户端关闭（默认情况下）或者 Session 超时都会失效。
* 存储大小不同： 单个 Cookie 保存的数据不能超过 4K，Session 可存储数据远高于 Cookie，但是当访问量过多，会占用过多的服务器资源。

## 什么是 Token（令牌）
token 是客户端访问服务端时所需要的资源凭证。客户端每一次请求都需要携带 token，需要把 token 放到 HTTP 的 Header 里。基于 token 的用户认证是一种服务端无状态的认证方式，服务端不用存放 token 数据。用解析 token 的计算时间换取 session 的存储空间，从而减轻服务器的压力，减少频繁的查询数据库。token 完全由应用管理，所以它可以避开同源策略。

![](https://chengzw258.oss-cn-beijing.aliyuncs.com/Article/20210502224649.png)

token 的身份验证流程：
* 客户端使用用户名跟密码请求登录。
* 服务端收到请求，去验证用户名与密码。
* 验证成功后，服务端会签发一个 token 并把这个 token 发送给客户端。
* 客户端收到 token 以后，会把它存储起来，比如放在 cookie 里或者 localStorage 里。
* 客户端每次向服务端请求资源的时候需要带着服务端签发的 token。
* 服务端收到请求，然后去验证客户端请求里面带着的 token ，如果验证成功，就向客户端返回请求的数据。

## JWT 介绍
JSON Web Token（简称 JWT）是目前最流行的跨域认证解决方案，是一种认证授权机制。
JWT 是为了在网络应用环境间传递声明而执行的一种基于 JSON 的开放标准（RFC 7519）。JWT 的声明一般被用来在身份提供者和服务提供者间传递被认证的用户身份信息，以便于从资源服务器获取资源。比如用在用户登录上。
可以使用 HMAC 算法或者是 RSA 的公/私秘钥对 JWT 进行签名。因为数字签名的存在，这些传递的信息是可信的。

### JWT 格式
JWT 的数据结构如下图所示：

![](https://chengzw258.oss-cn-beijing.aliyuncs.com/Article/20210502232517.png)

它是一个很长的字符串，中间用点 `.`分隔成三个部分。注意，JWT 内部是没有换行的，这里只是为了便于展示，将它写成了几行。

JWT 的三个部分依次如下：

```sh
Header（头部）
Payload（负载）
Signature（签名）
```
#### Header
Header 部分是一个 JSON 对象，描述 JWT 的元数据，通常是下面的样子：

```sh
{
  "alg": "HS256",
  "typ": "JWT"
}
```

上面代码中，alg属性表示签名的算法（algorithm），默认是 HMAC SHA256（写成 HS256）；typ属性表示这个令牌（token）的类型（type），JWT 令牌统一写为 JWT。最后，将上面的 JSON 对象使用 Base64URL 算法（详见后文）转成字符串。

#### Payload
Payload 部分也是一个 JSON 对象，用来存放实际需要传递的数据。JWT 规定了7个官方字段，供选用：

```sh
iss (issuer)：签发人
exp (expiration time)：过期时间
sub (subject)：主题
aud (audience)：受众
nbf (Not Before)：生效时间
iat (Issued At)：签发时间
jti (JWT ID)：编号
```

除了官方字段，你还可以在这个部分定义私有字段，下面就是一个例子：

```sh
{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true
}
```
前面提到，Header 和 Payload 串型化的算法是 Base64URL。这个算法跟 Base64 算法基本类似，但有一些小的不同。

JWT 作为一个令牌（token），有些场合可能会放到 URL（比如 api.example.com/?token=xxx）。Base64 有三个字符`+`、`/`和`=`，在 URL 里面有特殊含义，所以要被替换掉：`=`被省略、`+`替换成`-`，`/`替换成`_ `。这就是 Base64URL 算法。

#### Signature
Signature 部分是对前两部分的签名，防止数据篡改。
首先，需要指定一个密钥（secret）。这个密钥只有服务器才知道，不能泄露给用户。然后，使用 Header 里面指定的签名算法（默认是 HMAC SHA256），按照下面的公式产生签名。

```sh
HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload),secret)
```
算出签名以后，把 Header、Payload、Signature 三个部分拼成一个字符串，每个部分之间用 `.` 分隔，就可以返回给用户。

#### JWT 的使用方式
客户端收到服务器返回的 JWT，可以储存在 Cookie 里面，也可以储存在 localStorage。
此后，客户端每次与服务器通信，都要带上这个 JWT。你可以把它放在 Cookie 里面自动发送，但是这样不能跨域，所以更好的做法是放在 HTTP 请求的头信息Authorization字段里面。

```sh
Authorization: Bearer <jwt token>
```
服务端收到 JWT Token 后，使用密钥进行解密，就可以得到客户端的相应信息了，不需要再去数据库查询客户端信息。

## Token 和 JWT
* 相同：
    * 都是访问资源的令牌。
    * 都可以记录用户的信息。
    * 都是使服务端无状态化。
    * 都是只有验证成功后，客户端才能访问服务端上受保护的资源。

* 区别：
    * Token：服务端验证客户端发送过来的 Token 时，还需要查询数据库获取用户信息，然后验证 Token 是否有效。
    * JWT：将 Token 和 Payload 加密后存储于客户端，服务端只需要使用密钥解密进行校验（校验也是 JWT 自己实现的）即可，不需要查询或者减少查询数据库，因为 JWT 自包含了用户信息和加密的数据。

## JWT 实现
github地址：https://github.com/cr7258/jwt-lab，
本例使用 JJWT（Java JWT）来创建和验证 JSON Web Token（JWT）。

### 添加依赖
创建一个 Maven 项目并添加相关依赖：

```xml
 <dependencies>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-api</artifactId>
            <version>0.11.2</version>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-impl</artifactId>
            <version>0.11.2</version>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt-jackson</artifactId> <!-- or jjwt-gson if Gson is preferred -->
            <version>0.11.2</version>
            <scope>runtime</scope>
        </dependency>
        <!-- Uncomment this next dependency if you are using JDK 10 or earlier and you also want to use
             RSASSA-PSS (PS256, PS384, PS512) algorithms.  JDK 11 or later does not require it for those algorithms:
        <dependency>
            <groupId>org.bouncycastle</groupId>
            <artifactId>bcprov-jdk15on</artifactId>
            <version>1.60</version>
            <scope>runtime</scope>
        </dependency>
        -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
            <version>2.1.5.RELEASE</version>
        </dependency>
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>1.2.58</version>
        </dependency>
    </dependencies>
```
### 编写过滤器
编写过滤器，对请求验证 token：

```java
package com.chengzw.filter;

import com.chengzw.util.JwtService;
import io.jsonwebtoken.Claims;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * 过滤器，判断请求是否包含token
 * @author 程治玮
 * @since 2021/5/3 10:48 上午
 */
public class MyFilter implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest request =(HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;

        response.setCharacterEncoding("utf-8");
        String token = request.getHeader("authorization"); //获取请求传来的token
        if( token == null){
            response.getWriter().write("请携带token");
            return;
        }
        Claims claims = JwtService.parsePersonJWT(token); //验证token
        if (claims == null) {
            response.getWriter().write("请携带token");
        }else {
            filterChain.doFilter(request,response);
        }
    }
}
```
### 注册过滤器
注册过滤器，并添加需要过滤的 URI 路径 /user/hello：

```java
package com.chengzw.conf;

import com.chengzw.filter.MyFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 过滤器进行注册，并添加需要过滤的路径 /user/hello
 * @author 程治玮
 * @since 2021/5/3 10:37 上午
 */
@Configuration
public class BeanRegisterConfig {

    @Bean
    public FilterRegistrationBean createFilterBean() {
        //过滤器注册类
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(new MyFilter());
        registration.addUrlPatterns("/user/hello"); //需要过滤的接口
        return registration;
    }
}
```

### 编写JWT基础工具类
JWT 基础工具类包含两个部分：创建 JWT 和解析 JWT，JWS 是加密签名后的 JWT ，创建 JWS 主要有如下四步：

```java
String jws = Jwts.builder() // 创建 JwtBulder 实例
    .setSubject("Bob")      // 添加 Header 参数和声明
    .signWith(key)          // 指定希望对 JWT 签名的密钥（可以是对称密钥，也可以是非对称密钥的私钥）
    .compact();             // 压缩和签名 
```
具体实现代码：
```java
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
     * jwt = 头部（至少指定算法） + 身体（JWT编码的所有声明） + 签名（将标题和正文的组合通过标题中指定的算法计算得出）
     * jws:JWT可以加密签名成为jws
     * 创建token
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
```

### 封装 JWT 基础工具类
对 JWT 基础工具类进行二次封装，提供加密和解密的方法：

```java
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
```
### 编写 Controller 入口类
Controller 类提供用户访问的入口：

```java
package com.chengzw.controller;

import com.chengzw.util.JwtService;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @author 程治玮
 * @since 2021/5/3 10:45 上午
 */
@RestController
public class LoginController {

    //需要token验证才能访问
    @RequestMapping("user/hello")
    public String user(){
        return "hello";
    }


    //获取token
    @RequestMapping("user/token")
    public String token(){
        Map<String, Object> map = new HashMap<>();
        map.put("name", "chengzw");
        map.put("age", 21);
        return JwtService.createPersonToken(map, "chengzw");
    }
}
```

### 接口测试
第一次直接请求 /user/hello，会提示我们需要携带 token：

```sh
❯ curl http://localhost:8080/user/hello
请携带token
```
获取 token：

```sh
❯ curl http://localhost:8080/user/token

#返回token
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MjAwMTIwMTEsInN1YiI6IntuYW1lPWNoZW5nencsIGFnZT0yMX0iLCJpc3MiOiIwOGIxMDFjNC1hMmFjLTQ1OWQtYjU2ZS0wM2FkZTk2OWIwODYiLCJqdGkiOiJDWlciLCJhdWQiOiJjaGVuZ3p3IiwiZXhwIjoxNjIwMDE0NjAzLCJuYmYiOjE2MjAwMTIwMTF9.ZKX5Z3Acajg57MUQJZqFPWVpPbAGBIDiGigm4FgwmqM
```
然后在请求 Header 中带上 token 就可以成功访问了：

```sh
❯ curl http://localhost:8080/user/hello  -H "Authorization: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MjAwMTIwMTEsInN1YiI6IntuYW1lPWNoZW5nencsIGFnZT0yMX0iLCJpc3MiOiIwOGIxMDFjNC1hMmFjLTQ1OWQtYjU2ZS0wM2FkZTk2OWIwODYiLCJqdGkiOiJDWlciLCJhdWQiOiJjaGVuZ3p3IiwiZXhwIjoxNjIwMDE0NjAzLCJuYmYiOjE2MjAwMTIwMTF9.ZKX5Z3Acajg57MUQJZqFPWVpPbAGBIDiGigm4FgwmqM"
#返回结果
hello
```
## 参考链接
* https://blog.csdn.net/lh_hebine/article/details/99695927
* https://mp.weixin.qq.com/s/lJjY-l244P3cheYDhRQugw
* https://lijinhongpassion.github.io/codeant/61fc.html
* https://github.com/jwtk/jjwt
