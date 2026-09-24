package in.industrend.identity.auth;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
@Component
public class SecurityTokens {
  private final SecureRandom random=new SecureRandom(); private final byte[] pepper;
  public SecurityTokens(@Value("${app.security.otp-pepper}") String pepper){this.pepper=pepper.getBytes(StandardCharsets.UTF_8);}
  public String otp(){return Integer.toString(100000+random.nextInt(900000));}
  public String token(){byte[] b=new byte[32];random.nextBytes(b);return Base64.getUrlEncoder().withoutPadding().encodeToString(b);}
  public String hash(String value){try{Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(pepper,"HmacSHA256"));return hex(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));}catch(Exception e){throw new IllegalStateException(e);}}
  public boolean matches(String expected,String value){return MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),hash(value).getBytes(StandardCharsets.US_ASCII));}
  private String hex(byte[] bytes){var b=new StringBuilder();for(byte x:bytes)b.append(String.format("%02x",x));return b.toString();}
}