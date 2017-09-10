/******************************************************************************
 * Copyright (c) 2010 Masatomi KINO and others. 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * Contributors:
 *      Masatomi KINO - initial API and implementation
 * $Id$
 ******************************************************************************/
//作成日: 2017/07/23

package nu.mine.kino.utils;

import java.io.IOException;
import java.net.URL;
import java.text.ParseException;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

/**
 * @author Masatomi KINO
 * @version $Revision$
 */
public class JSONUtils {

    public static Map<String, Object> json2Map(String result)
            throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(result,
                new TypeReference<Map<String, Object>>() {
                });
    }

    public static String toPrettyStr(Object obj)
            throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper()
                .enable(SerializationFeature.INDENT_OUTPUT);
        return mapper.writeValueAsString(obj);
    }

    /**
     * 指定されたURLから、JWKを取得
     * 
     * @param url
     * @return
     * @throws IOException
     * @throws ParseException
     */
    private static JWKSet getJWKSet(String url)
            throws IOException, ParseException {
        // HTTP connect timeout in milliseconds
        int connectTimeout = 1000;

        // HTTP read timeout in milliseconds
        int readTimeout = 1000;

        // JWK set size limit, in bytes
        int sizeLimit = 10000;

        // The URL
        JWKSet publicKeys = JWKSet.load(new URL(url), connectTimeout,
                readTimeout, sizeLimit);
        return publicKeys;

    }

    public static RSAKey getRSAKey(String url, String keyID)
            throws IOException, ParseException {
        JWKSet publicKeys = getJWKSet(url);
        JWK key = publicKeys.getKeyByKeyId(keyID);
        RSAKey rsaKey = RSAKey.parse(key.toJSONObject());
        return rsaKey;
    }

}
