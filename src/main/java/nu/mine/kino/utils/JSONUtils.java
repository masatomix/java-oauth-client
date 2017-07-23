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
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

/**
 * @author Masatomi KINO
 * @version $Revision$
 */
public class JSONUtils {
    public static Map<String, Object> json2Map(String result) throws IOException {
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

    public static String toStr(Object obj) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(obj);
    }
}
