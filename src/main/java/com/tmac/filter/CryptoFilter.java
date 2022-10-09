package com.tmac.filter;


import com.alibaba.fastjson.JSON;
import com.tmac.constant.RsaConstants;
import com.tmac.utils.RsaUtil;
import lombok.SneakyThrows;
import org.apache.tomcat.util.codec.binary.Base64;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * 解密
 */
public class CryptoFilter implements Filter {


////    @Value("${crypto.specialUrlPatterns}")
//    private static final String specialUrlPatterns = "/train/wechat/login,/train/wechat/getLoginUser";
//
//    // 令牌自定义标识
////    @Value("${token.header}")
//    private static final String header = "Authorization";

//    @Autowired
//    private RedisCache redisCache;

    @SneakyThrows
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String requestURI = httpServletRequest.getRequestURI();
//        String privateKey = Strings.EMPTY;
//        String publicKey = Strings.EMPTY;
        //单独配置的特殊路径,用固定的2套私钥秘钥
//        if(specialUrlPatterns.contains(requestURI)){
//            publicKey = RsaConstants.LOGIN_PUBLICKEY;
//            privateKey = RsaConstants.LOGIN_PRIVATEKEY;
//        }else {
//            String token = ((HttpServletRequest) request).getHeader("Authorization");
//            if (Validator.isNotEmpty(token) && token.startsWith(Constants.TOKEN_PREFIX)) {
//                token = token.replace(Constants.TOKEN_PREFIX, "");
//                Object cacheObject = redisCache.getCacheObject(RedisConstants.RSA_KEY_CUSTOM + token);
//                Map<String,Object> map = JSONObject.parseObject(JSON.toJSONString(cacheObject));
//                publicKey = map.get(RsaConstants.PUBLIC_KEY).toString();
//                privateKey = map.get(RsaConstants.PRIVATE_KEY).toString();
//            }
//        }

        //获取参数 get/formdata
        Map<String, String> paramMap = parseRequestMap(request.getParameterMap());
        //解密后的map
        Map<String, String> decryptParamMap = new HashMap<>();
        if(paramMap.size() > 0){
            decryptParamMap = this.decryptParam(paramMap, RsaConstants.LOGIN_PRIVATEKEY);
        }

        //创建包装类对象，我们改写完数据后需要把参数重新放到这个类里面，传递到controller
        MyHttpServletRequestWrapper mHSReqW = new MyHttpServletRequestWrapper((HttpServletRequest)request, RsaConstants.LOGIN_PRIVATEKEY);
        if(paramMap.size() > 0){
            for (Map.Entry<String, String> entry : decryptParamMap.entrySet()) {
                mHSReqW.addParameter(entry.getKey(), entry.getValue());
            }
        }

//        //获取接口请求方式
//        String contentType = httpServletRequest.getMethod();
//        switch (contentType){
//            case "GET":
//                for (Map.Entry<String, String> entry : decryptParamMap.entrySet()) {
//                    mHSReqW.addParameter(entry.getKey(), entry.getValue());
//                }
//                break;
//        }
        //这里是重点，一定要把mHSReqW而不是request放进来，这样contoller就能收到我们解密后的参数了：request.getParameter("parameter");
//        chain.doFilter(mHSReqW, response);

//        //创建包装类对象，我们改写完数据后需要把参数重新放到这个类里面，传递到controller
//        MyHttpServletRequestWrapper mHSReqW = new MyHttpServletRequestWrapper((HttpServletRequest)request);
//        String parameter = request.getParameter("card");
//        String value= CryptoUtil.decrypt(parameter);//解密
//        mHSReqW.addParameter("card", value);//把键值对放进mHSReqW 里，便于传回controller
//        chain.doFilter(mHSReqW, response);//这里是重点，一定要把mHSReqW而不是request放进来，这样contoller就能收到我们解密后的参数了：request.getParameter("parameter");

        //下面写对返回数据response进行拦截修改
        MyHttpServletResponseWrapper mHSResW = new MyHttpServletResponseWrapper((HttpServletResponse)response);//转换成代理类
        //这里做前面对request拦截并解密那些事儿
        chain.doFilter(mHSReqW, mHSResW);//这里是最重要的一步，看到没，是把mHSResW放进去，不是前面把response放进去！！！！
        //controller已经把数据封装到缓冲区中，这里是取出来
        byte[] bytes = mHSResW.getBytes(); // 获取缓存的响应数据，看到没，是从我们前面放进去的mHSResW中取的
//        String utf8Str = new String(bytes, StandardCharsets.UTF_8);

        System.out.println("返回数据大小：" + bytes.length);
        if(bytes.length>0){
//            String info = new BASE64Encoder().encode(bytes);//这里就是关于加密的另一个坑，我们需要在这里用base64进行编码转换成String，而不能直接用new String（bytes，“utf-8”）来获取，因为这么转换会丢失字节，导致加密完，到了客户端无法正常解密，同样，加密类那里需要用base64获取字节（换成被注释掉的那句），而不是以前的String.getBytes（），这是关于字节数组转字符串一定要注意的地方。
//            String info = new String(bytes, "utf-8");
            //这一步encode,前端再decode, 才能保证中文不乱码
            String encode = URLEncoder.encode(new String(bytes), "utf-8");
            //这步很重要,上一步encode会导致空格变加号,这里转回空格, 不然你会遇到各种各样奇怪的报错
            String str = encode.replaceAll("\\+", "%20");
            String cryptoStr = RsaUtil.encryptByPublicKey(str.getBytes(), RsaConstants.LOGIN_PUBLICKEY).replaceAll("\r\n", "");//加密完太长的话会产生换行符，所以需要去掉
            Map<String,Object> map=new HashMap<String, Object>();
            map.put("responseBody", cryptoStr);
            String responseBody = JSON.toJSONString(map);//重新包装成json字符串
            HttpServletResponse hSResponse = (HttpServletResponse) response;//获取response，我们狸猫换太子终究是假的，返回数据最终还是需要真正的HttpServletResponse
            //这里如果清空buff会导致前端接口接受不到返回值
//            hSResponse.reset();//清空buff，不然传回数据会丢失一部分
            OutputStream op = hSResponse.getOutputStream();//获取输出流并写入我们改写的加密数据
            op.write(responseBody.getBytes(StandardCharsets.UTF_8));
            op.close();
        }

    }

    /**
     * 获取参数 get/formdata
     * @param map
     * @return
     */
    public static Map<String,String> parseRequestMap(Map<String, String[]> map){
        Map<String, String> params = new HashMap<String,String>();
        int len;
        for (Map.Entry<String, String[]> entry : map.entrySet()) {
            len = entry.getValue().length;
            if (len == 1) {
                params.put(entry.getKey(), entry.getValue()[0]);
            } else if (len > 1) {
                params.put(entry.getKey(), String.valueOf(entry.getValue()));
            }
        }
        return params;
    }

    /**
     * 获取参数 RequestBody
     * @param request
     * @return
     */
    public String getBodytxt(HttpServletRequest request) {
        BufferedReader br = null;
        try {
            br = request.getReader();
            String str, wholeStr = "";
            while((str = br.readLine()) != null){
                wholeStr += str;
            }
            return wholeStr;
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 参数解密后返回map
     * @param map
     * @return
     */
    public Map<String,String> decryptParam(Map<String,String> map,  String privateKey) throws Exception {
        Map<String,String> resultMap = new HashMap<>();
        for (Map.Entry<String, String> entry : map.entrySet()) {
            byte[] bytes = Base64.decodeBase64(entry.getValue());
            resultMap.put(entry.getKey(), RsaUtil.decryptByPrivateKey(bytes, privateKey));
        }
        return resultMap;
    }



}
