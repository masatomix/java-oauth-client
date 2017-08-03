package nu.mine.kino;

import static nu.mine.kino.Constants.SESSION_NONCE;
import static nu.mine.kino.Constants.SESSION_STATE;
import static nu.mine.kino.utils.JSONUtils.json2Map;
import static nu.mine.kino.utils.JSONUtils.toPrettyStr;
import static nu.mine.kino.utils.Utils.base64DecodeStr;
import static nu.mine.kino.utils.Utils.checkCSRF;
import static nu.mine.kino.utils.Utils.checkIdToken;
import static nu.mine.kino.utils.Utils.getAccessTokenJSON;
import static nu.mine.kino.utils.Utils.getRandomString;
import static nu.mine.kino.utils.Utils.getRequestURL;
import static nu.mine.kino.utils.Utils.getResource;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLEncoder;
import java.util.Enumeration;
import java.util.Map;
import java.util.ResourceBundle;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.ws.rs.BadRequestException;

import org.apache.commons.lang3.StringUtils;

import com.fasterxml.jackson.core.JsonProcessingException;

import lombok.extern.slf4j.Slf4j;;

/**
 * Servlet implementation class RedirectServlet
 */
// @WebServlet("/RedirectServlet")
@Slf4j
public class RedirectServlet extends HttpServlet {
    private static final long serialVersionUID = -4054957515370180691L;

    private ResourceBundle bundle = null;

    private static final String PARAM_AUTHORIZATION_CODE = "code";

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

    /**
     * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
     *      response)
     */
    protected void doGet(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {

        String redirect_url = getRequestURL(request);
        String encodedRedirectUrl = URLEncoder.encode(redirect_url, "UTF-8");
        log.debug("redirect_url:[{}]", redirect_url);// ココでセットするURLは、通常OAuthサーバ側に登録されているURLでなければならない。

        String client_id = bundle.getString("client_id");
        String client_secret = bundle.getString("client_secret");
        String authorization_endpoint = bundle
                .getString("authorization_endpoint");
        String token_endpoint = bundle.getString("token_endpoint");
        String userinfo_endpoint = bundle.getString("userinfo_endpoint");
        String jwks_uri = bundle.getString("jwks_uri");

        String authorizationCode = request
                .getParameter(PARAM_AUTHORIZATION_CODE);

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

            HttpSession session = request.getSession(true);
            log.debug("はじめのsession id: {}", session.getId());
            log.debug("session state: {}", state);
            session.setAttribute(SESSION_STATE, state);
            session.setAttribute(SESSION_NONCE, nonce);

            // OAuth Serverへリダイレクト
            response.sendRedirect(oauth_server_url);

        } else {
            // Access TokenとID Tokenの取得処理

            // CSRF対策のための、パラメタから取得したヤツと、Sessionにあるヤツの値を確認
            checkCSRF(request);

            String result = getAccessTokenJSON(token_endpoint, redirect_url,
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
                out.append("AccessToken: \n");
                out.append(toPrettyStr(map));

                // OpenID Connect対応でないと、id_tokenが返ってこない場合もある。
                if (StringUtils.isNotEmpty(id_token)) {
                    printIdToken(id_token, out);
                    boolean checkResult = checkIdToken(id_token, jwks_uri);
                    out.append("署名検証結果: " + checkResult);
                }
                out.append("\n\n");

                // OAuth2.0のみのアプリだと、明確にuserinfo_endpointがない場合もありそう
                if (StringUtils.isNotEmpty(userinfo_endpoint)) {
                    log.debug("Userinfo Endpoint Server:{}", userinfo_endpoint);
                    String userInfoJSON = getResource(userinfo_endpoint,
                            accessToken);
                    out.append("User Information: \n");
                    out.append(toPrettyStr(json2Map(userInfoJSON)));
                }

            } catch (BadRequestException e) {
                throw new ServletException(e);
            }
        }
    }

    private void printIdToken(String id_token, PrintWriter out)
            throws JsonProcessingException, IOException {

        String[] id_token_parts = id_token.split("\\.");

        String ID_TOKEN_HEADER = base64DecodeStr(id_token_parts[0]);
        String ID_TOKEN_PAYLOAD = base64DecodeStr(id_token_parts[1]);
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
        // TODO Auto-generated method stub
        doGet(request, response);
    }

}
