package com.paytend.api.service;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.IdUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONUtil;
import cn.hutool.log.Log;
import cn.hutool.log.LogFactory;
import com.paytend.api.utils.AESUtils;
import com.paytend.api.utils.PaytendUtil;
import com.paytend.api.utils.RSAUtils;

import java.io.File;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

/**
 * @author wanghuaiqing
 * @description
 * @date 2023/9/12 15:18
 */
public class CardService {

    private static final Log log = LogFactory.get();

  private static final String PAYTEND_BASE_URL = "https://sandbox-api.paytend.com";
    private static final String PAYTEND_PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDewAbc0xlYqEBM7X5Ud4KntDBjTjzbsXFg42RfYCFEt/DKkJluefqA0iWVmmOdnKYh7b7Mh5Y3mPSCbqOsEBkMHmjsT9qcVIVSeNDiWd2Djn/WCZTHMj7arsp2EkqXmSI5iGFxvq98hQ2ITMj34MtTla62I5uJFKayiD1vZKKxuQIDAQAB";
    private static final String PARTNER_ID = "888666000100201";
    private static final String PARTNER_PRIVATE_KEY = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAN7ABtzTGVioQEztflR3gqe0MGNOPNuxcWDjZF9gIUS38MqQmW55+oDSJZWaY52cpiHtvsyHljeY9IJuo6wQGQweaOxP2pxUhVJ40OJZ3YOOf9YJlMcyPtquynYSSpeZIjmIYXG+r3yFDYhMyPfgy1OVrrYjm4kUprKIPW9korG5AgMBAAECgYAHVo4jUjUAjbJoll5WDAXa3n3Fl7s7hZH1nigdWD5gVCrzkWXslMoi2klwr0Be3d0/OuTROhpBxKExdtGfhnw8sTvEj+FxvhFyoCT7DbuZr81WKpI7ncCGafDDC142B+D4oWsP2XrGGqSfWbq9/DRRXBMFWPNSLCQMNagMiRWcnQJBAPD/5ZiAvc+WWttww5vT3+fCL83EuqSH02Tt2jAIvjiD73l7vuqpEdjFoq4RJXpeu5j86AJA/msPPLAXdEw0aPMCQQDsnVdjSCC9tSPFvLPSteBuiMT0gLOBuOfuEKoY46eQ4KFINGZIvvdexCmjr+lKhgUljqhPCzOTJ7j98U+9tGWjAkA4T4KFFKfFJluKZJnAAkyR6WSkDrCRmw8AyTau/Iv9xo4g85ITYHfED8HILEd2hUYOJCHNzQPlXgUPHBvXZnOTAkEAsV8hayNep9dqAYj7pDEDFNkiC8eOyOe7tRJ48D94FXrObDobktzUww15yWLNFzhwEz9lnBthhiZ43qROin740QJASqiQ5egVBSkGk7IUrISUtz/FFY+ZjBi63fr+LLSu5INOJx/qNaAh6iQQ7+5hZr8QXLOgxx2cE9IES3cGbfICwQ==";
    private static final String VERSION = "2.0";
    private static final String SIGN_TYPE = "RSA";

    public static void main(String[] args) throws Exception {
        //1:Partner Interface

        queryPartnerBalance();//Query partner balance
//        queryPartnerTopupInformation();//Query partner topup information
//        partnerTransactionInformation();//Query partner transaction information

        //2:Cardholder Interface
//        queryCities();//Query cities
//        createCardholder();//Create cardholder
//        queryCardholder();//Query cardholder
//        updateCardholder();//Update cardholder
//        uploadSupportingDocuments();//Upload supporting documents
        //3:Card Interface
//        queryCardDesign();//Query card design style,Paytend后台提前购卡时可忽略此接口
//        applyCard();//Apply card,Paytend后台提前购卡时可忽略此接口
//        queryApplyResult();//Query apply result
//        activeCard();//Active card
//        queryCardInformation();//Query card information
//        queryCardBalance();//Query card balance
//        topup();//Topup
//        queryTopupResult();//Query topup result
//        reportLoss();//Report loss
//        cancelReportLoss();//Cancel report loss
//        retrievePassword();//Retrieve password
//        queryTransactionInformation();//Query transaction information
//        queryAuthorizationTransactions();//Query authorization transactions

    }

    /**
     * 创建持卡人
     *
     * @return
     * @throws Exception
     */
    public static void createCardholder() throws Exception {
        // 创建一个新的HashMap
        Map<String, Object> bizData = new HashMap<>();

        // EEA 地址
        Map<String, Object> eeaAddress = new HashMap<>();
        eeaAddress.put("addressLine", Base64.encode("Pamenkalnio st. 25-1"));
        eeaAddress.put("addressLine2", Base64.encode(""));
        eeaAddress.put("cityCode", "LT_MA");
        eeaAddress.put("state", "");
        eeaAddress.put("postcode", "LT-01113");
        eeaAddress.put("countryCode", "LT");


        // 设置值
        bizData.put("mobile", "+8618300000000");
        bizData.put("firstName", Base64.encode("Lv"));
        bizData.put("lastName", Base64.encode("Zhigang"));
        bizData.put("idNo", "PS1234567");
        bizData.put("idType", "2");
        bizData.put("email", "lzg@paytend.com");
        bizData.put("birthday", "1999-09-09");
        bizData.put("gender", "1");
        bizData.put("nationalityCode", "CN");
        bizData.put("eeaAddress", eeaAddress);

        String requestStr = initCommonRequest(JSONUtil.toJsonStr(bizData), true);
        log.debug("REQUEST:{}", JSONUtil.toJsonPrettyStr(requestStr));
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/holder/createCardholder", requestStr);
        handleResponse(responseStr);
    }

    /**
     * Update cardholder
     *
     * @param
     * @return
     * @throws Exception
     */
    public static void updateCardholder() throws Exception {
        // 创建一个新的HashMap
        Map<String, Object> bizData = new HashMap<>();

        // EEA 地址
        Map<String, Object> eeaAddress = new HashMap<>();
        eeaAddress.put("addressLine", Base64.encode("Pamenkalnio st. 25-1 update"));
        eeaAddress.put("addressLine2", Base64.encode(""));
        eeaAddress.put("cityCode", "LT_MA");
        eeaAddress.put("state", "");
        eeaAddress.put("postcode", "LT-update");
        eeaAddress.put("countryCode", "LT");

        // 设置值
        bizData.put("holderId", "101982");
        bizData.put("birthday", "1994-01-01");
        bizData.put("gender", "2");
        bizData.put("nationalityCode", "LT");
        bizData.put("eeaAddress", eeaAddress);

        String requestStr = initCommonRequest(JSONUtil.toJsonStr(bizData), true);
        log.debug("REQUEST:{}", JSONUtil.toJsonPrettyStr(requestStr));
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/holder/updateCardholder", requestStr);
        handleResponse(responseStr);
    }

    /**
     * Query cardholder
     *
     * @return
     * @throws Exception
     */
    public static void queryCardholder() throws Exception {
        // 创建一个新的HashMap
        Map<String, Object> bizData = new HashMap<>();
        // 设置值
        bizData.put("holderId", "101982");
        bizData.put("idNo", "");
        bizData.put("idType", "");

        log.debug("bizData:{}", JSONUtil.toJsonPrettyStr(bizData));
        String requestStr = initCommonRequest(JSONUtil.toJsonStr(bizData), true);
        log.debug("REQUEST:{}", JSONUtil.toJsonPrettyStr(requestStr));
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/holder/getHolder", requestStr);
        handleResponse(responseStr);
    }

    /**
     * Upload supporting documents
     *
     * @return
     * @throws Exception
     */
    public static void uploadSupportingDocuments() throws Exception {
        // 创建一个新的HashMap
        Map<String, Object> bizData = new HashMap<>();
        // 设置值
        bizData.put("holderId", "101982");
        bizData.put("fileType", "3");
        bizData.put("fileContent", Base64.encode(new File("D:\\DirMove\\Pictures\\Saved Pictures\\photo_3.jpg")));
        bizData.put("suffix", ".jpeg");

        String requestStr = initCommonRequest(JSONUtil.toJsonStr(bizData), true);
        log.debug("REQUEST:{}", JSONUtil.toJsonPrettyStr(requestStr));
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/holder/uploadDocument", requestStr);
        handleResponse(responseStr);
    }

    /**
     * Query cities
     *
     * @return
     * @throws Exception
     */
    public static void queryCities() throws Exception {
        // 创建一个新的HashMap
        Map<String, Object> bizData = new HashMap<>();
        // 设置值
        bizData.put("countryCode", "LT");
        bizData.put("start", "1");
        bizData.put("maxResult", "30");

        String requestStr = initCommonRequest(JSONUtil.toJsonStr(bizData), true);
        log.debug("REQUEST:{}", JSONUtil.toJsonPrettyStr(requestStr));
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/holder/getCities", requestStr);
        handleResponse(responseStr);
    }

    public static void queryCardDesign() throws Exception {
        // 创建一个新的HashMap
        String requestStr = initCommonRequest("", true);
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/card/getSKUs", requestStr);
        handleResponse(responseStr);
    }

    /**
     * Apply card
     *
     * @return
     * @throws Exception
     */
    public static void applyCard() throws Exception {
        // 创建一个新的HashMap
        Map<String, Object> bizData = new HashMap<>();

        // deliveryAddress
        Map<String, Object> deliveryAddress = new HashMap<>();
        deliveryAddress.put("addressLine", Base64.encode("Pamenkalnio st. 25-1"));
        deliveryAddress.put("addressLine2", Base64.encode(""));
        deliveryAddress.put("cityCode", "LT_MA");
        deliveryAddress.put("state", "");
        deliveryAddress.put("postcode", "LT-01113");
        deliveryAddress.put("countryCode", "LT");

        // 设置值
        bizData.put("orderNo", "CARD2023110600002");
//        bizData.put("holderId", "101982");
        bizData.put("cardScheme", "3");
        bizData.put("cardType", "2");
        bizData.put("sku", "CTHMCPE20056");
        bizData.put("remarks", "");
        bizData.put("quantity", "2");
        bizData.put("contactName", "Lv Zhigang");
        bizData.put("contactMobile", "+8618300000000");
        bizData.put("deliveryAddress", deliveryAddress);

        String requestStr = initCommonRequest(JSONUtil.toJsonStr(bizData), true);
        log.debug("REQUEST:{}", JSONUtil.toJsonPrettyStr(requestStr));
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/card/applyCard", requestStr);
        handleResponse(responseStr);
    }

    /**
     * Active card
     *
     * @return
     * @throws Exception
     */
    public static void activeCard() throws Exception {
        // 创建一个新的HashMap
        Map<String, Object> bizData = new HashMap<>();

        // 设置值
        bizData.put("cardId", "1755902");
        bizData.put("holderId", "101982");

        String requestStr = initCommonRequest(JSONUtil.toJsonStr(bizData), true);
        log.debug("REQUEST:{}", JSONUtil.toJsonPrettyStr(requestStr));
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/card/activeCard", requestStr);
        handleResponse(responseStr);
    }

    /**
     * Topup
     *
     * @return
     * @throws Exception
     */
    public static void topup() throws Exception {
        // 创建一个新的HashMap
        Map<String, Object> bizData = new HashMap<>();

        // 设置值
        bizData.put("cardId", "1755902");
        bizData.put("orderNo", "TOPUP2023110600000");
        bizData.put("amount", "1100");
        bizData.put("currency", "EUR");

        String requestStr = initCommonRequest(JSONUtil.toJsonStr(bizData), true);
        log.debug("REQUEST:{}", JSONUtil.toJsonPrettyStr(requestStr));
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/card/topup", requestStr);
        handleResponse(responseStr);
    }

    /**
     * Replace card
     *
     * @return
     * @throws Exception
     */
    public static void replaceCard() throws Exception {
        // 创建一个新的HashMap
        Map<String, Object> bizData = new HashMap<>();

        // 设置值
        bizData.put("cardId", "");
        bizData.put("cvv", "");
        bizData.put("oldCardId", "");

        String requestStr = initCommonRequest(JSONUtil.toJsonStr(bizData), true);
        log.debug("REQUEST:{}", JSONUtil.toJsonPrettyStr(requestStr));
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/card/replaceCard", requestStr);
        handleResponse(responseStr);
    }


    /**
     * Report loss
     *
     * @return
     * @throws Exception
     */
    public static void reportLoss() throws Exception {
        // 创建一个新的HashMap
        Map<String, Object> bizData = new HashMap<>();

        // 设置值
        bizData.put("cardId", "1755902");

        String requestStr = initCommonRequest(JSONUtil.toJsonStr(bizData), true);
        log.debug("REQUEST:{}", JSONUtil.toJsonPrettyStr(requestStr));
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/card/lostCard", requestStr);
        handleResponse(responseStr);
    }


    /**
     * Cancel report loss
     *
     * @return
     * @throws Exception
     */
    public static void cancelReportLoss() throws Exception {
        // 创建一个新的HashMap
        Map<String, Object> bizData = new HashMap<>();

        // 设置值
        bizData.put("cardId", "1755902");

        String requestStr = initCommonRequest(JSONUtil.toJsonStr(bizData), true);
        log.debug("REQUEST:{}", JSONUtil.toJsonPrettyStr(requestStr));
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/card/cancelCardLost", requestStr);
        handleResponse(responseStr);
    }

    /**
     * Retrieve password
     *
     * @return
     * @throws Exception
     */
    public static void retrievePassword() throws Exception {
        // 创建一个新的HashMap
        Map<String, Object> bizData = new HashMap<>();

        // 设置值
        bizData.put("cardId", "1755902");

        String requestStr = initCommonRequest(JSONUtil.toJsonStr(bizData), true);
        log.debug("REQUEST:{}", JSONUtil.toJsonPrettyStr(requestStr));
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/card/retrievePassword", requestStr);
        handleResponse(responseStr);
    }

    /**
     * Retrieve password
     *
     * @return
     * @throws Exception
     */
    public static void queryApplyResult() throws Exception {
        // 创建一个新的HashMap
        Map<String, Object> bizData = new HashMap<>();

        // 设置值
        bizData.put("orderNo", "CARD2023110600002");
//        bizData.put("orderNo", "CARD2023110600001");
//        bizData.put("holderId", "101982");

        String requestStr = initCommonRequest(JSONUtil.toJsonStr(bizData), true);
        log.debug("REQUEST:{}", JSONUtil.toJsonPrettyStr(requestStr));
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/card/getApplyCardResult", requestStr);
        handleResponse(responseStr);
    }

    /**
     * Query card information
     *
     * @return
     * @throws Exception
     */
    public static void queryCardInformation() throws Exception {
        // 创建一个新的HashMap
        Map<String, Object> bizData = new HashMap<>();

        // 设置值
//        bizData.put("cardId", "1755902");
        bizData.put("cardId", "1755891");


        String requestStr = initCommonRequest(JSONUtil.toJsonStr(bizData), true);
        log.debug("REQUEST:{}", JSONUtil.toJsonPrettyStr(requestStr));
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/card/getCardInfo", requestStr);
        handleResponse(responseStr);
    }

    /**
     * Query topup result
     *
     * @return
     * @throws Exception
     */
    public static void queryTopupResult() throws Exception {
        // 创建一个新的HashMap
        Map<String, Object> bizData = new HashMap<>();

        // 设置值
        bizData.put("orderNo", "TOPUP2023110600000");

        String requestStr = initCommonRequest(JSONUtil.toJsonStr(bizData), true);
        log.debug("REQUEST:{}", JSONUtil.toJsonPrettyStr(requestStr));
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/card/getTopupResult", requestStr);
        handleResponse(responseStr);
    }

    /**
     * Query transaction information
     *
     * @return
     * @throws Exception
     */
    public static void queryTransactionInformation() throws Exception {
        // 创建一个新的HashMap
        Map<String, Object> bizData = new HashMap<>();

        // 设置值
        bizData.put("cardId", "1755902");
        bizData.put("transactionStatus", "");
        bizData.put("currency", "");
        bizData.put("beginDate", "2023-11-06");
        bizData.put("endDate", "2023-11-06");
        bizData.put("start", "");
        bizData.put("maxSize", "");

        String requestStr = initCommonRequest(JSONUtil.toJsonStr(bizData), true);
        log.debug("REQUEST:{}", JSONUtil.toJsonPrettyStr(requestStr));
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/card/getCardTransactions", requestStr);
        handleResponse(responseStr);
    }

    /**
     * Query transaction information
     *
     * @return
     * @throws Exception
     */
    public static void queryAuthorizationTransactions() throws Exception {
        // 创建一个新的HashMap
        Map<String, Object> bizData = new HashMap<>();

        // 设置值
        bizData.put("cardId", "1755902");
        bizData.put("currency", "");
        bizData.put("beginDate", "2023-11-06");
        bizData.put("endDate", "2023-11-06");
        bizData.put("start", "");
        bizData.put("maxSize", "");

        String requestStr = initCommonRequest(JSONUtil.toJsonStr(bizData), true);
        log.debug("REQUEST:{}", JSONUtil.toJsonPrettyStr(requestStr));
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/card/getAuthorizationTransactions", requestStr);
        handleResponse(responseStr);
    }

    /**
     * Query card design style
     *
     * @return
     * @throws Exception
     */
    public static void queryCardDesignStyle() throws Exception {
        // 创建一个新的HashMap
        Map<String, Object> bizData = new HashMap<>();

        String requestStr = initCommonRequest(JSONUtil.toJsonStr(bizData), true);
        log.debug("REQUEST:{}", JSONUtil.toJsonPrettyStr(requestStr));
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/card/getSKUs", requestStr);
        handleResponse(responseStr);
    }

    /**
     * Query card balance
     *
     * @return
     * @throws Exception
     */
    public static void queryCardBalance() throws Exception {
        // 创建一个新的HashMap
        Map<String, Object> bizData = new HashMap<>();

        // 设置值
        bizData.put("cardId", "1755902");
//        bizData.put("cardId", "1755891");

        String requestStr = initCommonRequest(JSONUtil.toJsonStr(bizData), true);
        log.debug("REQUEST:{}", JSONUtil.toJsonPrettyStr(requestStr));
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/card/getCardBalance", requestStr);
        handleResponse(responseStr);
    }

    /**
     * Query partner balance
     *
     * @return
     * @throws Exception
     */
    public static void queryPartnerBalance() throws Exception {
        // 创建一个新的HashMap
        Map<String, Object> bizData = new HashMap<>();

        String requestStr = initCommonRequest(JSONUtil.toJsonStr(bizData), true);
        log.debug("REQUEST:{}", JSONUtil.toJsonPrettyStr(requestStr));
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/partner/getPartnerBalance", requestStr);
        handleResponse(responseStr);
    }

    /**
     * Query partner topup information
     *
     * @return
     * @throws Exception
     */
    public static void queryPartnerTopupInformation() throws Exception {
        // 创建一个新的HashMap
        Map<String, Object> bizData = new HashMap<>();

        // 设置值
        bizData.put("currency", "EUR");

        String requestStr = initCommonRequest(JSONUtil.toJsonStr(bizData), true);
        log.debug("REQUEST:{}", JSONUtil.toJsonPrettyStr(requestStr));
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/partner/getPartnerTopup", requestStr);
        handleResponse(responseStr);
    }

    /**
     * Query partner transaction information
     *
     * @return
     * @throws Exception
     */
    public static void partnerTransactionInformation() throws Exception {
        // 创建一个新的HashMap
        Map<String, Object> bizData = new HashMap<>();

        // 设置值
        bizData.put("transactionStatus", "");
        bizData.put("currency", "");
        bizData.put("beginDate", "2023-11-06");
        bizData.put("endDate", "2023-11-06");
        bizData.put("start", "");
        bizData.put("maxSize", "");
        log.debug("bizData:{}", JSONUtil.toJsonPrettyStr(bizData));
        String requestStr = initCommonRequest(JSONUtil.toJsonStr(bizData), true);
        log.debug("REQUEST:{}", JSONUtil.toJsonPrettyStr(requestStr));
        String responseStr = PaytendUtil.postJson(PAYTEND_BASE_URL + "/issuing/partner/getPartnerTransactions", requestStr);
        handleResponse(responseStr);
    }

    /**
     * 初始化 公共请求信息
     *
     * @return
     */
    public static String initCommonRequest(String requestStr, boolean isAES) throws Exception {
        String aesKey = AESUtils.generateKey();

        Map<String, Object> commonRequestMap = new HashMap<>();

        commonRequestMap.put("requestId", PARTNER_ID + PaytendUtil.genOutTradeNo());
        commonRequestMap.put("partnerId", PARTNER_ID);
        commonRequestMap.put("version", VERSION);
        commonRequestMap.put("signType", SIGN_TYPE);
        commonRequestMap.put("bizData", requestStr);
        commonRequestMap.put("randomKey", aesKey);
        String signDataString = getTreeValue(commonRequestMap, false);
        System.out.println("signData" + JSONUtil.parseObj(commonRequestMap));
        System.out.println("signDataString:" + signDataString);
        commonRequestMap.put("signature", RSAUtils.signSHA256(signDataString.getBytes("UTF-8"), PARTNER_PRIVATE_KEY));

        if(requestStr != null && !requestStr.equals("")){
            commonRequestMap.put("bizData", isAES == true ? AESUtils.encrypt(requestStr, aesKey) : JSONUtil.parseObj(requestStr));
        }
        commonRequestMap.put("randomKey", RSAUtils.encryptPublicKey(aesKey, PAYTEND_PUBLIC_KEY));
        return JSONUtil.toJsonStr(commonRequestMap);
    }

    /**
     * 处理响应
     *
     * @param responseStr
     * @return
     * @throws Exception
     */
    public static void handleResponse(String responseStr) throws Exception {
        log.debug(responseStr);
        Map<String, Object> responseMap = JSONUtil.toBean(responseStr, Map.class);

        String respCode = String.valueOf(responseMap.get("respCode"));
        if (!"00".equals(respCode)) {
            log.debug("Request exception");
            log.debug(JSONUtil.toJsonStr(responseStr));
            return;
        }

        String randomKey = String.valueOf(responseMap.get("randomKey"));
        String respData = String.valueOf(responseMap.get("respData"));
        String signature = String.valueOf(responseMap.get("signature"));

        /**
         * randomKey RSA 解密
         */
        String randomKeyMsg = RSAUtils.decryptPrivateKey(randomKey, PARTNER_PRIVATE_KEY);
        responseMap.put("randomKey", randomKeyMsg);
        /**
         * respData AES 解密
         */
        String respDataMsg = "";
        if(respData != null && !respData.equals("")){
            respDataMsg = AESUtils.decrypt(respData, randomKeyMsg);
            responseMap.put("respData", JSONUtil.parseObj(respDataMsg));
        }
        /**
         * 验证 signature
         */
        responseMap.remove("encryptFlag");// 预留字段 不参与签名
        responseMap.remove("signature"); // 不参与签名
        String signDataString = getTreeValue(responseMap, false); // 计算签名串
        boolean flag = RSAUtils.verifySHA256(signDataString.getBytes("UTF-8"), PAYTEND_PUBLIC_KEY, signature);

        if (flag) {
            log.debug("RESPONSE:{}", JSONUtil.toJsonPrettyStr(responseMap));
        } else {
            log.debug("Response verification fail");
        }

    }

    public static String getTreeValue(Map<String, Object> toSortData, boolean emptyParamIsSign) {
        TreeMap<String, Object> params = new TreeMap<String, Object>();
        params.putAll(toSortData);
        StringBuffer orgin = new StringBuffer();
        Iterator<String> iter = params.keySet().iterator();
        while (iter.hasNext()) {
            String key = iter.next();
            String value = String.valueOf(params.get(key));
            if (emptyParamIsSign) {//空值参数参与签名
                orgin.append("&").append(key).append("=").append(value);
            } else {//空值参数不参与签名
                if (!StrUtil.isEmpty(value)) {
                    orgin.append("&").append(key).append("=").append(value);
                }
            }
        }
        return orgin.toString().substring(1);
    }
}
