package com.fastchar.security.template;

import com.fastchar.core.FastChar;
import com.fastchar.security.exception.FastSecurityException;
import com.fastchar.security.utils.RSABuilder;
import com.fastchar.utils.FastFileUtils;
import com.fastchar.utils.FastMD5Utils;
import com.fastchar.utils.FastStringUtils;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FastSecurityAuto {

    public static String ProjectPath = null;

    private static String replacePlaceholder(Map<String, Object> placeholders, String content) {
        for (String key : placeholders.keySet()) {
            if (placeholders.get(key) != null) {
                content = content.replaceAll("\\$\\{" + key + "}", placeholders.get(key).toString());
                content = content.replaceAll("\\$\\[" + key + "]", placeholders.get(key).toString());
            }
        }
        return content;
    }

    private static String formatString(String target, int targetLength) {
        StringBuilder targetBuilder = new StringBuilder(target);
        while (FastStringUtils.truthLength(targetBuilder.toString()) < targetLength) {
            targetBuilder.append(" ");
        }
        target = targetBuilder.toString();
        return target + "： ";
    }

    public static void buildMd5() {
        try {
            if (FastStringUtils.isEmpty(ProjectPath)) {
                throw new FastSecurityException("项目路径不可为空！请配置FastSecurityAuto.ProjectPath值！");
            }

            String md5Key = FastMD5Utils.MD5(System.getenv().toString() + System.currentTimeMillis());
            Map<String, Object> params = new HashMap<>();
            params.put("key", md5Key);

            URL javascriptTemplate = FastSecurityAuto.class.getResource("md5_javascript");
            File javascriptFile = new File(ProjectPath, "/security/md5/fast-security.js");
            FastFileUtils.copyURLToFile(javascriptTemplate, javascriptFile);
            String javascript = FastFileUtils.readFileToString(javascriptFile, "utf-8");
            FastFileUtils.writeStringToFile(javascriptFile, replacePlaceholder(params, javascript));

            URL androidTemplate = FastSecurityAuto.class.getResource("md5_android");
            File androidFile = new File(ProjectPath, "/security/md5/android_code.txt");
            FastFileUtils.copyURLToFile(androidTemplate, androidFile);
            String android = FastFileUtils.readFileToString(androidFile, "utf-8");
            FastFileUtils.writeStringToFile(androidFile, replacePlaceholder(params, android));

            URL iosTemplate = FastSecurityAuto.class.getResource("md5_ios");
            File iosFile = new File(ProjectPath, "/security/md5/ios_code.txt");
            FastFileUtils.copyURLToFile(iosTemplate, iosFile);
            String ios = FastFileUtils.readFileToString(iosFile, "utf-8");
            FastFileUtils.writeStringToFile(iosFile, replacePlaceholder(params, ios));

            List<String> infos = new ArrayList<>();
            infos.add("\n" + formatString("1、MD5加签的密钥", 25) + md5Key);
            infos.add(formatString("2、JavaScript 代码文件", 25) + javascriptFile.getAbsolutePath());
            infos.add(formatString("3、Android 代码文件", 25) + androidFile.getAbsolutePath());
            infos.add(formatString("4、Object-C 代码文件", 25) + iosFile.getAbsolutePath());
            infos.add("\n使用说明：");
            infos.add("* 请设置 FastSecurityConfig.securityModule 模式为 FastSecurityConfig.MD5_PARAMS_SIGN ");
            infos.add("* 请将（1、MD5加签的密钥）配置到 FastSecurityConfig.md5Key 中！");
            infos.add("* JavaScript的密钥直接存在代码中，建议在进行JavaScript文件加密混淆！");
            infos.add("* 在线混淆：https://javascriptobfuscator.com/Javascript-Obfuscator.aspx");
            infos.add("\n构建成功！");

            StringBuilder infoBuilder = new StringBuilder();
            for (String info : infos) {
                infoBuilder.append(info).append("\n");
            }
            System.out.println(FastChar.getLog().lightStyle(infoBuilder.toString()));
            File buildFile = new File(ProjectPath, "/security/md5/build-info.txt");
            FastFileUtils.writeStringToFile(buildFile, infoBuilder.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void buildRsa() {
        buildRsa(1024);
    }

    public static void buildRsa(int keyLength) {
        try {
            if (FastStringUtils.isEmpty(ProjectPath)) {
                throw new FastSecurityException("项目路径不可为空！请配置FastSecurityAuto.ProjectPath值！");
            }

            String md5Key = FastMD5Utils.MD5(System.getenv().toString() + System.currentTimeMillis());
            Map<String, Object> params = new HashMap<>();
            params.put("key", md5Key);

            File publicKey = new File(ProjectPath, "security/rsa/rsa_public_" + keyLength + ".pem");
            RSABuilder rsaBuilder = new RSABuilder()
                    .setKeyLength(keyLength)
                    .setPrivateKeyFile(new File(ProjectPath, "security/rsa/rsa_private_" + keyLength + ".pem").getAbsolutePath())
                    .setPrivateKeyPkcs8File(new File(ProjectPath, "security/rsa/rsa_private_pkcs8_" + keyLength + ".pem").getAbsolutePath())
                    .setPublicKeyFile(publicKey.getAbsolutePath());
            rsaBuilder.builder();

            StringBuilder stringBuilder = new StringBuilder();
            List<String> strings = FastFileUtils.readLines(publicKey);
            for (String string : strings) {
                if (string.startsWith("--")) {
                    continue;
                }
                stringBuilder.append(string);
            }
            params.put("publicKey", stringBuilder.toString());


            URL javascriptTemplate = FastSecurityAuto.class.getResource("rsa_javascript");
            File javascriptFile = new File(ProjectPath, "/security/rsa/fast-security.js");
            FastFileUtils.copyURLToFile(javascriptTemplate, javascriptFile);
            String javascript = FastFileUtils.readFileToString(javascriptFile, "utf-8");
            FastFileUtils.writeStringToFile(javascriptFile, replacePlaceholder(params, javascript));


            URL androidTemplate = FastSecurityAuto.class.getResource("rsa_android");
            File androidFile = new File(ProjectPath, "/security/rsa/android_code.txt");
            FastFileUtils.copyURLToFile(androidTemplate, androidFile);
            String android = FastFileUtils.readFileToString(androidFile, "utf-8");
            FastFileUtils.writeStringToFile(androidFile, replacePlaceholder(params, android));

            URL iosTemplate = FastSecurityAuto.class.getResource("rsa_ios");
            URL iosToolATemplate = FastSecurityAuto.class.getResource("ios_rsa.h");
            URL iosToolBTemplate = FastSecurityAuto.class.getResource("ios_rsa.m");
            File iosFile = new File(ProjectPath, "/security/rsa/ios/ios_code.txt");
            File iosToolAFile = new File(ProjectPath, "/security/rsa/ios/RSA.h");
            File iosToolMFile = new File(ProjectPath, "/security/rsa/ios/RSA.m");
            FastFileUtils.copyURLToFile(iosTemplate, iosFile);
            FastFileUtils.copyURLToFile(iosToolATemplate, iosToolAFile);
            FastFileUtils.copyURLToFile(iosToolBTemplate, iosToolMFile);
            String ios = FastFileUtils.readFileToString(iosFile, "utf-8");
            FastFileUtils.writeStringToFile(iosFile, replacePlaceholder(params, ios));

            List<String> infos = new ArrayList<>();
            infos.add("\n");
            infos.add(formatString("1、RSA 加密密钥", 25) + md5Key);
            infos.add(formatString("2、RSA 私钥文件", 25) + rsaBuilder.getPrivateKeyFile());
            infos.add(formatString("3、RSA 私钥pkcs8文件", 25) + rsaBuilder.getPrivateKeyPkcs8File());
            infos.add(formatString("4、RSA 公钥文件", 25) + rsaBuilder.getPublicKeyFile());
            infos.add(formatString("5、JavaScript 代码文件", 25) + javascriptFile.getAbsolutePath());
            infos.add(formatString("6、Android 代码文件", 25) + androidFile.getAbsolutePath());
            infos.add(formatString("7、Object-C 代码文件", 25) + iosFile.getAbsolutePath());
            infos.add("\n");
            infos.add("使用说明：");
            infos.add("* 请设置 FastSecurityConfig.securityModule 模式为 FastSecurityConfig.RSA_HEADER_TOKEN ");
            infos.add("* 请将（1、RSA加密的密钥）配置到 FastSecurityConfig.rsaPassword 中！");
            infos.add("* 请将（3、RSA 私钥pkcs8文件）配置到 FastSecurityConfig.rsaPrivateKeyPkcs8 中！");
            infos.add("* JavaScript的密钥直接存在代码中，建议在进行JavaScript文件加密混淆！");
            infos.add("* 在线混淆：https://javascriptobfuscator.com/Javascript-Obfuscator.aspx");
            infos.add("\n");
            infos.add("构建成功！");
            StringBuilder infoBuilder = new StringBuilder();
            for (String info : infos) {
                infoBuilder.append(info).append("\n");
            }
            System.out.println(FastChar.getLog().lightStyle(infoBuilder.toString()));
            File buildFile = new File(ProjectPath, "/security/rsa/build-info.txt");
            FastFileUtils.writeStringToFile(buildFile, infoBuilder.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


}
