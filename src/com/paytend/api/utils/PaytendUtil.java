package com.paytend.api.utils;

import cn.hutool.core.util.StrUtil;
import cn.hutool.http.HttpRequest;
import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;

import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * @author wanghuaiqing
 * @description paytend 工具类
 * @date 2023/9/12 9:24
 */
public class PaytendUtil {

    /**
     * 日志
     */
    public static Log logger = LogFactory.get();


    /**
     * post json
     *
     * @param url
     * @param paramStr
     * @return
     */
    public static String postJson(String url, String paramStr) {
        long startTime = System.currentTimeMillis();
        cn.hutool.http.HttpResponse response = null;
        try {
            response = HttpRequest.post(url).body(paramStr).execute();
            logger.info("sendPostJson url {}, param {}. result: code {}, ret: {}, cost: {}", url,
                    getExeFileString(paramStr), response.getStatus(), response.body(), System.currentTimeMillis() - startTime);
        } catch (Exception e) {
            logger.error("sendPostForm exception, url {}, param {}, cost: {}", getExeFileString(paramStr), paramStr,
                    System.currentTimeMillis() - startTime, e);
        }
        return response.body();
    }

    private static String getExeFileString(String param) {
        if (StrUtil.isNotBlank(param)) {
            return param.replaceAll("(\"[a-zA-Z]*template\":)(\"[^\"]+\")", "#");
        }
        return param;
    }



    /**
     * 生成订单号
     *
     * @return String
     */
    public static String genOutTradeNo() {
        SimpleDateFormat sd = new SimpleDateFormat("yyyyMMddHHmmssSSS");
        return sd.format(new Date());
    }

}
