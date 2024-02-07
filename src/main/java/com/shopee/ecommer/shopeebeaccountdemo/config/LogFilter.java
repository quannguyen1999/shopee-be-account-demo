//package com.shopee.ecommer.shopeebeaccountdemo.config;
//
//import jakarta.servlet.*;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.core.Ordered;
//import org.springframework.core.annotation.Order;
//import org.springframework.stereotype.Component;
//
//import java.io.IOException;
//import java.time.LocalDateTime;
//import java.util.Collection;
//import java.util.Enumeration;
//
//@Slf4j
//@Component
//@Order(Ordered.HIGHEST_PRECEDENCE)
//public class LogFilter implements Filter {
//
//    @Override
//    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
//            throws IOException, ServletException {
//
//        HttpServletRequest httpRequest = (HttpServletRequest) request;
//        HttpServletResponse httpResponse = (HttpServletResponse) response;
//        LocalDateTime date = LocalDateTime.now();
//        log.debug("LogFilter: " + date + " - " + httpRequest.getLocalAddr() + ":" + httpRequest.getLocalPort() + httpRequest.getServletPath());
//        log.debug("Request:");
//        Enumeration<String> headers = httpRequest.getHeaderNames();
//        while (headers.hasMoreElements()) {
//            String headerName = headers.nextElement();
//            log.debug("\tHeader: " + headerName + ":" + httpRequest.getHeader(headerName));
//        }
//        log.debug("\n");
//        Enumeration<String> parameters = httpRequest.getParameterNames();
//        while (parameters.hasMoreElements()) {
//            String parameterName = parameters.nextElement();
//            log.debug("\tParameter: " + parameterName + ": " + httpRequest.getParameter(parameterName));
//        }
//        log.debug("\nResponse:");
//        chain.doFilter(request, response);
//        Collection<String> responseHeaders = httpResponse.getHeaderNames();
//        responseHeaders.forEach(x -> log.debug("\tHeader: " + x + ": " + httpResponse.getHeader(x)));
//        log.debug("\n\n");
//    }
//
//}