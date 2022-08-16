package com.itheima.pinda.zuul.filter;

import cn.hutool.core.util.StrUtil;
import com.itheima.pinda.base.R;
import com.itheima.pinda.common.adapter.IgnoreTokenConfig;
import com.netflix.zuul.ZuulFilter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import com.netflix.zuul.context.RequestContext;
import javax.servlet.http.HttpServletRequest;

/**
 * 基础过滤器
 */
@Slf4j
public abstract class BaseFilter extends ZuulFilter {
    @Value("${server.servlet.context-path}")
    protected String zuulPrefix;
    //判断当前请求的URI是否需要忽略（直接放行），不是所有资源都需要鉴权
    protected boolean isIgnoreToken(){
        //动态获取当前请求URI
        HttpServletRequest request = RequestContext.getCurrentContext().getRequest();
        String uri=request.getRequestURI();
        //uri= StrUtil.subSuf(uri,uri.indexOf(zuulPrefix.length()));
        //uri= StrUtil.subSuf(uri,uri.indexOf("/",1));
        uri = StrUtil.subSuf(uri, zuulPrefix.length());
        uri = StrUtil.subSuf(uri, uri.indexOf("/", 1));
        boolean ignoreToken= IgnoreTokenConfig.isIgnoreToken(uri);
        return ignoreToken;
    }

    protected void errorResponse(String errMsg,int errCode,int httpStatusCode){
        RequestContext ctx = RequestContext.getCurrentContext();
        //设置响应状态码
        ctx.setResponseStatusCode(httpStatusCode);
        //设置响应头信息
        ctx.addZuulResponseHeader("Content-Type","application/json;charset=utf-8");
        if(ctx.getResponseBody()==null){
            //设置响应体
            ctx.setResponseBody(R.fail(errCode,errMsg).toString());
            //不进行路由，直接返回
            ctx.setSendZuulResponse(false);
        }
    }
}
