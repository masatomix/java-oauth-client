package nu.mine.kino;

import static nu.mine.kino.utils.JSONUtils.*;
import static org.apache.commons.codec.binary.Base64.*;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLEncoder;
import java.text.ParseException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Map;
import java.util.ResourceBundle;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.BadRequestException;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.StatusType;

import org.apache.commons.lang3.RandomStringUtils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class RedirectServlet extends HttpServlet {

    protected void doGet(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {

        String redirect_url = new String(request.getRequestURL());
        String encodedRedirectUrl = URLEncoder.encode(redirect_url, "UTF-8");
        log.debug("redirect_url:[{}]", redirect_url);// ココでセットするURLは、通常OAuthサーバ側に登録されているURLでなければならない。

        String client_id = bundle.getString("client_id");
        String client_secret = bundle.getString("client_secret");
        String authorization_endpoint = bundle
                .getString("authorization_endpoint");
        String token_endpoint = bundle.getString("token_endpoint");
        String userinfo_endpoint = bundle.getString("userinfo_endpoint");
        String jwks_uri = bundle.getString("jwks_uri");

        String authorizationCode = request.getParameter("code");

        if (authorizationCode == null) {
            // Authorization Codeの取得開始。

            String oauth_server_url_format = authorization_endpoint //
                    + "?" //
                    + "client_id=%1$s&" //
                    + "redirect_uri=%2$s&" //
                    + "state=%3$s&" //
                    + "nonce=%4$s&" //
                    + "response_type=%5$s&"//
                    + "scope=%6$s";

            // CSRF対策のための、stateを設定
            String state = getRandomString();

            String nonce = getRandomString();
            String response_type = "code";
            String scope = "openid+profile+email";

            String oauth_server_url = String.format(oauth_server_url_format,
                    client_id, //
                    encodedRedirectUrl, //
                    state, //
                    nonce, //
                    response_type, //
                    scope);
            log.debug(oauth_server_url);

            // HttpSession session = request.getSession(true);
            // session.setAttribute(SESSION_STATE, state);
            // session.setAttribute(SESSION_NONCE, nonce);

            // OAuth Serverへリダイレクト
            response.sendRedirect(oauth_server_url);

        } else {
            // Access TokenとID Tokenの取得処理
            // CSRF対策のための、パラメタから取得したヤツと、Sessionにあるヤツの値を確認
            // checkCSRF(request);

            String result = getAccessToken(token_endpoint, redirect_url,
                    client_id, client_secret, authorizationCode);

            try {
                Map<String, Object> map = json2Map(result);
                String accessToken = (String) map.get("access_token");
                String id_token = (String) map.get("id_token");

                log.debug("access_token: {}", accessToken);
                log.debug("refresh_token: {}", map.get("refresh_token"));
                log.debug("id_token: {}", id_token);

                response.setContentType("text/plain;charset=UTF-8");
                PrintWriter out = response.getWriter();

                printDataFromResourceServer(accessToken, out);
                {
                    out.append("AccessToken: \n");
                    out.append(toPrettyStr(map));
                    out.append("\n\n");
                }
                printIdToken(id_token, out);
                {
                    boolean checkResult = checkIdToken(id_token, jwks_uri,
                            client_secret);
                    out.append("署名検証結果: " + checkResult);
                    out.append("\n\n");
                }
                {
                    out.append("User Information: \n");
                    log.debug("Userinfo Endpoint Server:{}", userinfo_endpoint);
                    String userInfoJSON = getResource(userinfo_endpoint,
                            accessToken);
                    out.append(toPrettyStr(json2Map(userInfoJSON)));
                    out.append("\n\n");
                }
            } catch (BadRequestException e) {
                throw new ServletException(e);
            }
        }
    }

    private void printDataFromResourceServer(String accessToken,
            PrintWriter out) throws JsonProcessingException, IOException {
        String sample_endpoint = bundle.getString("sample_endpoint");
        log.debug("Sample Endpoint: {}", sample_endpoint);
        String sampleData = getResource(sample_endpoint, accessToken);
        log.debug("Sample Data: {}", sampleData);

        out.append("Resource Server Result: \n");
        String curl = String.format(
                "curl %s -H \"Authorization: Bearer %s\" -G", sample_endpoint,
                accessToken);

        out.append(curl + "\n");
        out.append("とおなじ。\n");
        out.append(toPrettyStr(json2Map(sampleData)));
        out.append("\n\n");
    }

    private void printIdToken(String id_token, PrintWriter out)
            throws JsonProcessingException, IOException {

        String[] id_token_parts = id_token.split("\\.");

        String ID_TOKEN_HEADER = new String(decodeBase64(id_token_parts[0]));
        String ID_TOKEN_PAYLOAD = new String(decodeBase64(id_token_parts[1]));
        // String ID_TOKEN_SIGNATURE =
        // base64DecodeStr(id_token_parts[2]);
        log.debug("ID_TOKEN_HEADER: {}", ID_TOKEN_HEADER);
        log.debug("ID_TOKEN_PAYLOAD: {}", ID_TOKEN_PAYLOAD);
        // log.debug("ID_TOKEN_SIGNATURE: {}", ID_TOKEN_SIGNATURE);

        // ホントはPAYLOADの nonce値とSessionのnonce値の一致チェックが必要。まだやってない。

        out.append("OpenID ID TOKEN HEADER: \n");
        out.append(toPrettyStr(json2Map(ID_TOKEN_HEADER)));
        out.append("\n\n");

        out.append("OpenID ID TOKEN PAYLOAD: \n");
        out.append(toPrettyStr(json2Map(ID_TOKEN_PAYLOAD)));
        out.append("\n\n");

    }

    /**
     * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
     *      response)
     */
    protected void doPost(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
        doGet(request, response);
    }

    /**
     * レスポンスのHTTP Response Statusのチェック。400番台、500番台の場合例外
     * 
     * @param restResponse
     * @throws ServletException
     */
    private void checkAccessTokenResult(Response restResponse)
            throws ServletException {
        StatusType statusInfo = restResponse.getStatusInfo();
        switch (statusInfo.getFamily()) {
        case CLIENT_ERROR:
        case SERVER_ERROR:
            String message = String.format("Status: %s:[%s]",
                    statusInfo.getStatusCode(), statusInfo.getReasonPhrase());
            log.error("{}", restResponse.getStatusInfo());
            throw new ServletException(message);
        default:
            break;
        }
    }

    /**
     * AccessToken取得のためのMapを作成する。
     * 
     * @param redirect_url
     * @param client_id
     * @param client_secret
     * @param authorizationCode
     * @param client
     * @param mediaType
     * @return
     */
    private Map<String, ?> createMap(String redirect_url, String client_id,
            String client_secret, String authorizationCode, Client client) {

        String grant_type = "authorization_code";
        MultivaluedMap<String, String> formParams = new MultivaluedHashMap<String, String>();
        formParams.putSingle("redirect_uri", redirect_url);
        formParams.putSingle("grant_type", grant_type);
        formParams.putSingle("client_id", client_id);
        formParams.putSingle("client_secret", client_secret);
        formParams.putSingle("code", authorizationCode);

        return formParams;

    }

    private String getAccessToken(String oauth_server, String redirect_url,
            String client_id, String client_secret, String authorizationCode)
            throws ServletException {
        String result = null;

        Client client = ClientBuilder.newClient();
        Map<String, String> formParams = (Map<String, String>) createMap(
                redirect_url, client_id, client_secret, authorizationCode,
                client);

        log.debug("OAuthServer:{}", oauth_server);
        Response restResponse = client //
                .target(oauth_server) //
                .request(MediaType.APPLICATION_JSON_TYPE)
                .post(Entity.entity(formParams,
                        MediaType.APPLICATION_FORM_URLENCODED_TYPE));
        result = restResponse.readEntity(String.class);
        log.debug("result: {}", result);
        checkAccessTokenResult(restResponse);

        return result;

    }

    private String getResource(String target, String accessToken) {
        Client client = ClientBuilder.newClient();
        Response restResponse = client.target(target)
                .queryParam("schema", "openid")//
                .request(MediaType.APPLICATION_JSON_TYPE)
                .header("Authorization", "Bearer " + accessToken).get();

        String result = restResponse.readEntity(String.class);
        log.debug(result);
        return result;
    }

    private boolean checkHSSignature(SignedJWT decodeObject,
            byte[] sharedSecret) throws JOSEException {
        JWSVerifier verifier = new MACVerifier(sharedSecret);
        boolean verify = decodeObject.verify(verifier);
        log.debug("valid？: {}", verify);
        return verify;
    }

    private boolean checkRSSignature(SignedJWT decodeObject, String jwks_uri)
            throws JOSEException, IOException, ParseException {
        // Headerから KeyIDを取得して、
        String keyID = decodeObject.getHeader().getKeyID();
        log.debug("KeyID: {}", keyID);

        RSAKey rsaKey = getRSAKey(jwks_uri, keyID);
        JWSVerifier verifier = new RSASSAVerifier(rsaKey);
        boolean verify = decodeObject.verify(verifier);
        log.debug("valid？: {}", verify);
        return verify;
    }

    private boolean checkIdToken(String id_token, String jwks_uri,
            String secret) throws ServletException {
        // String[] id_token_parts = id_token.split("\\.");
        //
        // String ID_TOKEN_HEADER = base64DecodeStr(id_token_parts[0]);
        // String ID_TOKEN_PAYLOAD = base64DecodeStr(id_token_parts[1]);
        // // String ID_TOKEN_SIGNATURE =
        // // base64DecodeStr(id_token_parts[2]);
        // log.debug("ID_TOKEN_HEADER: {}", ID_TOKEN_HEADER);
        // log.debug("ID_TOKEN_PAYLOAD: {}", ID_TOKEN_PAYLOAD);
        // // log.debug("ID_TOKEN_SIGNATURE: {}", ID_TOKEN_SIGNATURE);

        try {
            // JWTの仕様に基づいて、デコードしてみる。
            SignedJWT decodeObject = SignedJWT.parse(id_token);
            log.debug("Header : " + decodeObject.getHeader());
            log.debug("Payload: " + decodeObject.getPayload());
            log.debug("Sign   : " + decodeObject.getSignature());

            JWSAlgorithm algorithm = decodeObject.getHeader().getAlgorithm();
            JWTClaimsSet set = decodeObject.getJWTClaimsSet();
            log.debug("Algorithm: {}", algorithm.getName());
            log.debug("Subject: {}", set.getSubject());
            log.debug("Issuer: {}", set.getIssuer());
            log.debug("Audience: {}", set.getAudience());
            log.debug("Nonce: {}", set.getClaim("nonce"));
            log.debug("now before ExpirationTime?: {}",
                    new Date().before(set.getExpirationTime()));

            if (algorithm.getName().startsWith("HS")) {
                log.debug("共通鍵({})", algorithm.getName());
                byte[] sharedSecret = secret.getBytes();
                return checkHSSignature(decodeObject, sharedSecret);
            } else {
                log.debug("公開鍵({})", algorithm.getName());
                return checkRSSignature(decodeObject, jwks_uri);
            }

        } catch (ParseException e) {
            log.warn("サーバの公開鍵の取得に失敗しています.{}", e.getMessage());
        } catch (IOException e) {
            log.warn("サーバの公開鍵の取得に失敗しています.{}", e.getMessage());
        } catch (JOSEException e) {
            log.warn("Verify処理に失敗しています。{}", e.getMessage());
        }
        return false;

    }

    private ResourceBundle bundle = null;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        String propertyFile = getServletConfig().getInitParameter("property");
        try {
            bundle = ResourceBundle.getBundle(propertyFile);
            doSettings(bundle);
        } catch (java.util.MissingResourceException e) {
            String message = "設定ファイルが存在しません。クラスパス上に {}.propertiesを配置してください。({})";
            log.error(message, propertyFile, e.getMessage());
            throw new ServletException(e);
        }
    }

    private void doSettings(ResourceBundle bundle) {
        Enumeration<String> keys = bundle.getKeys();
        while (keys.hasMoreElements()) {
            String key = keys.nextElement();
            log.debug("key[{}]:{}", key, bundle.getString(key));
        }
    }

    private String getRandomString() {
        return RandomStringUtils.randomAlphanumeric(40);
    }

    private static final long serialVersionUID = -4054957515370180691L;

    // private static final String SESSION_STATE = "state";
    //
    // private static final String PARAM_STATE = "state";

    // private static final String SESSION_NONCE = "nonce";
    //
    // private static final String PARAM_NONCE = "nonce";

    // /**
    // * CSRF対策。 セッションが存在するか、存在するなら、セッション内のstate 属性とリクエストパラメタのstateパラメタの値の一致チェック
    // *
    // * @param request
    // * @throws ServletException
    // */
    // private static void checkCSRF(HttpServletRequest request)
    // throws ServletException {
    // HttpSession session = request.getSession(false);
    // if (session == null) {
    // throw new ServletException("Bad Request(session is null.)");
    // }
    //
    // log.debug("Redirect後のsession id: {}", session.getId());
    // String requestState = request.getParameter(PARAM_STATE);
    // String sessionState = (String) session.getAttribute(SESSION_STATE);
    // log.debug("requestState:[{}]", requestState);
    // log.debug("sessionState:[{}]", sessionState);
    // if (!requestState.equals(sessionState)) {
    // throw new ServletException("前回のリクエストと今回のstate値が一致しないため、エラー。");
    // }
    // }

}
