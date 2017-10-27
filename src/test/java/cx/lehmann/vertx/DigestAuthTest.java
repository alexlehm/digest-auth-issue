package cx.lehmann.vertx;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientOptions;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.core.net.ProxyOptions;
import io.vertx.core.net.ProxyType;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.ext.web.client.WebClient;

/**
 * @author <a href="https://oss.lehmann.cx/">Alexander Lehmann</a>
 *
 */

@RunWith(VertxUnitRunner.class)
public class DigestAuthTest {
  private static final Logger log = LoggerFactory.getLogger(DigestAuthTest.class);
  //  private static final String PROXY_HOST = "localhost";
  //  private static final int PROXY_PORT = 3128;
  private static final int PORT = 18082;
  private static final String HOST = "localhost";
  private static final String URI = "/json_rpc";

  @Test
  @Ignore
  public void authTest() {
    parseAuth("Digest qop=\"auth\",algorithm=MD5,realm=\"monero-rpc\",nonce=\"RDMuwRyXPKUHn1vkgznTAQ==\",stale=false");
    String auth = getAuth();
    log.info("auth:"+auth);
  }

  @Test
  public void asyncTest(TestContext theContext) {

    log.info("test starting");

    Vertx vertx = Vertx.vertx();

    Async async = theContext.async();

    HttpClientOptions hco = new HttpClientOptions();
    //    hco.setProxyOptions(new ProxyOptions().setType(ProxyType.HTTP).setHost(PROXY_HOST).setPort(PROXY_PORT));
    //    hco.setLogActivity(true);
    hco.setMaxPoolSize(1);

    HttpClient httpclient = vertx.createHttpClient(hco);
    WebClient client = WebClient.wrap(httpclient);
    client.get(PORT, HOST, URI).send(ar -> {
      if(ar.succeeded()) {
        HttpResponse<Buffer> response = ar.result();
        log.info("WWW-Authenticate: "+response.getHeader("WWW-Authenticate"));
        parseAuth(response.getHeader("WWW-Authenticate"));
        String auth = getAuth();
        log.info("auth reply "+auth);
        client.get(PORT, HOST, URI)
        .putHeader(HttpHeaders.AUTHORIZATION.toString(), auth)
        .send(ar2 -> {
          if (ar2.succeeded()) {
            HttpResponse<Buffer> response2 = ar2.result();
            System.out.println(response2.statusCode());
            //              vertx.setTimer(5000, t1 -> async.complete());
            async.complete();
          }
        });
      } else {
        theContext.fail(ar.cause());
      }
    });
  }

  private String nonce;
  private long nc;
  private static final Pattern AUTH_PATTERN = Pattern.compile("Digest qop=\"auth\",algorithm=MD5,realm=\"monero-rpc\",nonce=\"(?<nonce>.+)\",stale=false");
  //  private static final Pattern AUTH_PATTERN = Pattern.compile("Digest realm=\"apache\", nonce=\"(?<nonce>.+)\", algorithm=MD5, qop=\"auth\"");

  private static final String METHOD = "GET";
  private static final String USER = "username";
  private static final String REALM = "monero-rpc";
  private static final String PASSWORD = "password";
  private static final String QOP = "auth";
  private static final String ALGORITHM = "MD5";

  private static final Random RANDOM = new Random();

  private void parseAuth(String header) {
    Matcher m = AUTH_PATTERN.matcher(header);
    if(m.matches()) {
      nc = 0;
      nonce = m.group("nonce");
    }
  }

  private String getAuth() {
    if(nonce != null) {
      final byte[] cnonceBytes = new byte[8];
      RANDOM.nextBytes(cnonceBytes);
      String clientNonce = bytesToHex(cnonceBytes);
      //      String clientNonce = "YWZhMmI0ZTZiZjZkYmY5MjcwOWVlMWRlZWYyMDEzYmY=";
      String nonceCount = String.format("%08x", ++nc);

      return getAuth(nonce, METHOD, clientNonce, nonceCount);
    } else {
      log.info("nonce is null");
      return null;
    }
  }

  private String getAuth(String nonce, String method, String clientNonce, String nonceCount) {
    String ha1 = md5(USER + ":" + REALM + ":" + PASSWORD);
    String ha2 = md5(method + ":" + URI);
    String response = md5(ha1 + ":" + nonce + ":" + nonceCount + ":" + clientNonce + ":" + QOP + ":" + ha2);


    return "Digest username=\"" + USER + "\", "+
    "realm=\"" + REALM + "\", "+
    "nonce=\"" + nonce + "\", "+
    "uri=\"" + URI + "\", "+
    "cnonce=\"" + clientNonce + "\", " +
    "nc=" + nonceCount + ", "+
    "qop=" + QOP + ", "+
    "response=\"" + response + "\", "+
    "algorithm=\"" + ALGORITHM + "\", state=true";
  }
  private static MessageDigest md5;
  static {
    try {
      md5= MessageDigest.getInstance("MD5");
    } catch (NoSuchAlgorithmException ex) {
      // TODO Auto-generated catch block
      ex.printStackTrace();
    };
  };

  private String md5(String payload) {
    return md5(payload.getBytes());
  }
  private String md5(byte[] payload) {
    md5.reset();
    return bytesToHex(md5.digest(payload));
  }
  private static final char[] HEXADECIMAL = "0123456789abcdef".toCharArray();
  private static String bytesToHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
    for ( int j = 0; j < bytes.length; j++ ) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = HEXADECIMAL[v >>> 4];
      hexChars[j * 2 + 1] = HEXADECIMAL[v & 0x0F];
    }
    return new String(hexChars);
  }

}
