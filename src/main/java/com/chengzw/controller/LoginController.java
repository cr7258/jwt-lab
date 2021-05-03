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