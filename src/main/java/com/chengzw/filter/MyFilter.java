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

