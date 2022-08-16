package com.itheima.pinda.zuul.filter;


import com.itheima.pinda.auth.client.properties.AuthClientProperties;
import com.itheima.pinda.auth.client.utils.JwtTokenClientUtils;
import com.itheima.pinda.auth.utils.JwtUserInfo;
import com.itheima.pinda.base.R;
import com.itheima.pinda.context.BaseContextConstants;
import com.itheima.pinda.exception.BizException;
import com.itheima.pinda.utils.StrHelper;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;

import static org.springframework.cloud.netflix.zuul.filters.support.FilterConstants.PRE_TYPE;

/**
 * 当前过滤器负责解析请求头中的jwt令牌，并且将解析出的用户信息放入zuul的header中
 */
public class TokenContextFilter extends BaseFilter {
    @Autowired
    private AuthClientProperties authClientProperties;
    @Autowired
    private JwtTokenClientUtils jwtTokenClientUtils;

    //过滤器类型
    @Override
    public String filterType() {
        return PRE_TYPE; //前置过滤器
    }

    //过滤器执行的顺序，数值越大执行越靠后
    @Override
    public int filterOrder() {
        /*
         一定要在org.springframework.cloud.netflix.zuul.filters.pre.PreDecorationFilter过滤器之后执行
         因为这个过滤器做了路由,而我们需要这个路由信息来鉴权，这个过滤器会将我们鉴权需要的信息放置在请求上下文中
         */
        return FilterConstants.PRE_DECORATION_FILTER_ORDER+1;
    }

    //是否执行当前过滤器
    @Override
    public boolean shouldFilter() {
        return true;
    }

    //真正的过滤逻辑
    @Override
    public Object run() throws ZuulException {
        if(isIgnoreToken()){
            //直接放行
            return null;
        }
        RequestContext ctx = RequestContext.getCurrentContext();
        HttpServletRequest request = ctx.getRequest();
        //从请求头中获取前端提交的jwt令牌
        String userToken = request.getHeader(authClientProperties.getUser().getHeaderName());

        JwtUserInfo userInfo=null;
        try{
            userInfo = jwtTokenClientUtils.getUserInfo(userToken);
        }catch (BizException e){
            errorResponse(e.getMessage(),e.getCode(),200);
            return null;
        }catch (Exception e){
            errorResponse("解析token出错", R.FAIL_CODE,200);
            return null;
        }
        if(userInfo!=null){
            addHeader(ctx, BaseContextConstants.JWT_KEY_ACCOUNT,userInfo.getAccount());
            addHeader(ctx, BaseContextConstants.JWT_KEY_USER_ID,userInfo.getUserId());
            addHeader(ctx, BaseContextConstants.JWT_KEY_NAME,userInfo.getName());
            addHeader(ctx, BaseContextConstants.JWT_KEY_ORG_ID,userInfo.getOrgId());
            addHeader(ctx, BaseContextConstants.JWT_KEY_STATION_ID,userInfo.getStationId());
        }

        return null;
    }

    private void addHeader(RequestContext ctx,String name,Object value){
        if(StringUtils.isEmpty(value)){
            return;
        }
        ctx.addZuulRequestHeader(name, StrHelper.encode(value.toString()));
    }
}
