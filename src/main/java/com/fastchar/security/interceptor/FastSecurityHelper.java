package com.fastchar.security.interceptor;

import com.fastchar.core.FastAction;
import com.fastchar.core.FastChar;
import com.fastchar.security.FastSecurityConfig;
import com.fastchar.security.exception.FastSecurityException;
import com.fastchar.utils.FastFileUtils;
import com.fastchar.utils.FastMD5Utils;
import com.fastchar.utils.FastStringUtils;

import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

class FastSecurityHelper {


    public static void validateMD5Sign(FastAction fastAction, FastSecurityConfig config) throws Exception {
        if (FastStringUtils.isEmpty(config.getMd5Key())) {
            throw new FastSecurityException("MD5加签的key不可为空！");
        }
        String signKey = config.getMd5Key();
        String paramSign = fastAction.getParam("sign", "NONE");

        if (FastChar.getCache().exists("Security", paramSign)) {
            fastAction.setStatus(400).responseText("非法访问！签名已失效！");
        }
        FastChar.getCache().set("Security", paramSign, true);

        TreeSet<String> keys = new TreeSet<>(fastAction.getParamNames());
        StringBuilder stringBuilder = new StringBuilder();
        for (String s : keys) {
            if (s.equals("sign")) {
                continue;
            }
            stringBuilder.append(s).append("=").append(fastAction.getParam(s)).append(";");
        }
        stringBuilder.append("key=").append(signKey).append(";");
        String serverSign = FastChar.getSecurity().MD5_Encrypt(stringBuilder.toString());
        if (!paramSign.equalsIgnoreCase(serverSign)) {
            fastAction.setStatus(400).responseText("非法访问！签名无效！");
        }
    }



    public static void validateRSA(FastAction fastAction, FastSecurityConfig config) throws Exception {
        String token = fastAction.getRequest().getHeader("token");
        if (FastStringUtils.isEmpty(token)) {
            fastAction.setStatus(400).responseText("非法访问！");
        }
        if (FastStringUtils.isEmpty(config.getRsaPrivateKeyPkcs8())) {
            throw new FastSecurityException("RSA验证的privateKey不可为空！");
        }

        if (FastStringUtils.isEmpty(config.getRsaPassword())) {
            throw new FastSecurityException("RSA验证的password不可为空！");
        }

        if (!config.isRsaInitial()) {
            config.setRsaInitial(true);
            String privateKey = config.getRsaPrivateKeyPkcs8();
            File privateKeyFile = new File(FastChar.getPath().getClassRootPath(),privateKey);
            if (privateKeyFile.exists()) {
                StringBuilder stringBuilder = new StringBuilder();
                List<String> strings = FastFileUtils.readLines(privateKeyFile);
                for (String line : strings) {
                    if (line.startsWith("-")) {
                        continue;
                    }
                    stringBuilder.append(line);
                }
                privateKey = stringBuilder.toString();
                config.setRsaPrivateKeyPkcs8(privateKey);
            }
        }

        String content = FastChar.getSecurity().RSA_Decrypt_PrivateKey(config.getRsaPrivateKeyPkcs8(), token);
        if (FastStringUtils.isEmpty(content)) {
            fastAction.setStatus(400).responseText("非法访问！Token无效！");
        }
        if (FastChar.getCache().exists("Security",content)) {
            fastAction.setStatus(400).responseText("非法访问！Token已失效！");
        }
        FastChar.getCache().set("Security", content, true);
        if (!content.startsWith(config.getRsaPassword())) {
            fastAction.setStatus(400).responseText("非法访问！Token密钥无效！");
        }

    }
}
