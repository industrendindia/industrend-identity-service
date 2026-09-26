package in.industrend.identity.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.springframework.stereotype.Component;

@Component
public class PinHasher {
  private static final int ITERATIONS = 210_000;
  private static final int KEY_BITS = 256;
  private final SecureRandom random = new SecureRandom();

  public String hash(String pin) {
    byte[] salt = new byte[16];
    random.nextBytes(salt);
    byte[] derived = derive(pin, salt, ITERATIONS);
    return "$pbkdf2-sha256$" + ITERATIONS + "$" + Base64.getUrlEncoder().withoutPadding().encodeToString(salt) + "$" + Base64.getUrlEncoder().withoutPadding().encodeToString(derived);
  }

  public boolean matches(String encoded, String pin) {
    try {
      String[] parts = encoded.split("\\$");
      int iterations = Integer.parseInt(parts[2]);
      byte[] salt = Base64.getUrlDecoder().decode(parts[3]);
      byte[] expected = Base64.getUrlDecoder().decode(parts[4]);
      return MessageDigest.isEqual(expected, derive(pin, salt, iterations));
    } catch (RuntimeException exception) {
      return false;
    }
  }

  private byte[] derive(String pin, byte[] salt, int iterations) {
    try {
      var spec = new PBEKeySpec(pin.toCharArray(), salt, iterations, KEY_BITS);
      return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    } catch (Exception exception) {
      throw new IllegalStateException("Unable to protect login PIN", exception);
    }
  }
}
