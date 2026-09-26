package in.industrend.identity.auth;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class PinHasherTest {
  private final PinHasher hasher = new PinHasher();

  @Test void hashesAndVerifiesWithoutStoringPlaintext() {
    var encoded = hasher.hash("482951");
    assertTrue(hasher.matches(encoded, "482951"));
    assertFalse(hasher.matches(encoded, "482952"));
    assertFalse(encoded.contains("482951"));
  }

  @Test void usesUniqueSaltForSamePin() {
    assertNotEquals(hasher.hash("482951"), hasher.hash("482951"));
  }
}
