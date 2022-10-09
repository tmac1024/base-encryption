package com.tmac.filter;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.tmac.exception.CustomException;
import com.tmac.utils.RsaUtil;
import com.tmac.utils.StringUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.codec.binary.Base64;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.*;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class MyHttpServletRequestWrapper extends HttpServletRequestWrapper {

    private final String body;

    private Map<String, String[]> params = new HashMap<String, String[]>();
    public MyHttpServletRequestWrapper(HttpServletRequest request,  String privateKey) throws Exception {
        super(request);
        this.params.putAll(request.getParameterMap());

        StringBuilder sb = new StringBuilder(128);
        BufferedReader br = null;
        try {
            InputStream is = request.getInputStream();
            if (is != null) {
                //br = new BufferedReader(new InputStreamReader(is));
                /**
                 * 当中文乱码时
                 * tomcat配置中加
                 * -Dfile.encoding=UTF-8
                 */
                br = new BufferedReader(new InputStreamReader(is,"UTF-8"));
                char[] charBuffer = new char[128];
                int byteRead = -1;
                while ((byteRead = br.read(charBuffer)) > 0) {
                    sb.append(charBuffer, 0, byteRead);
                }
            }
        } catch (IOException e) {
            log.error(e.getMessage());
            throw new CustomException("解密参数异常");
        } finally {
            if (br != null) {
                br.close();
            }
        }
        if(StringUtils.isNotEmpty(sb)){
            JSONObject jsonObject = JSON.parseObject(sb.toString());
            String requestBody = jsonObject.getString("requestBody");
            byte[] bytes = Base64.decodeBase64(requestBody);
            body = RsaUtil.decryptByPrivateKey(bytes, privateKey);
        }else {
            body = "";
        }
        if (log.isDebugEnabled()){
            log.debug("body:{}",body);
        }
    }
    /**
     * 重载构造函数
     * @param request
     * @param extraParams
     */
    public MyHttpServletRequestWrapper(HttpServletRequest request, Map<String, Object> extraParams,  String privateKey) throws Exception{
        this(request, privateKey);
        addParameters(extraParams);
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(body.getBytes());
        ServletInputStream servletInputStream = new ServletInputStream() {
            @Override
            public boolean isFinished() {
                return false;
            }

            @Override
            public boolean isReady() {
                return false;
            }

            @Override
            public void setReadListener(ReadListener readListener) {

            }

            @Override
            public int read() throws IOException {
                return byteArrayInputStream.read();
            }
        };
        return servletInputStream;
    }


    public void addParameters(Map<String, Object> extraParams) {
        for (Map.Entry<String, Object> entry : extraParams.entrySet()) {
            addParameter(entry.getKey(), entry.getValue());
        }
    }

    /**
     * 重写getParameter，代表参数从当前类中的map获取
     * @param name
     * @return
     */
    @Override
    public String getParameter(String name) {
//        String[]values = params.get(name);
//        if(values == null || values.length == 0) {
//            return null;
//        }
//        return values[0];
        //好像其实, 用上面的也不会影响
        String value=this.getRequest().getParameter(name);
        String result=null;
        try {
            if(null!=value)
                result=new String(value.getBytes("iso-8859-1"),"utf-8");
        } catch (UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return result;
    }

    /**
     * 同上
     * @param name
     * @return
     */
    @Override
    public String[] getParameterValues(String name) {
        return params.get(name);
    }

    /**
     * 添加参数
     * @param name
     * @param value
     */
    public void addParameter(String name, Object value) {
        if (value != null) {
            if (value instanceof String[]) {
                params.put(name, (String[]) value);
            } else if (value instanceof String) {
                params.put(name, new String[]{(String) value});
            } else {
                params.put(name, new String[]{String.valueOf(value)});
            }
        }
    }

}
