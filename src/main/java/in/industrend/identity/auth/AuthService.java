package in.industrend.identity.auth;

import com.fasterxml.jackson.annotation.JsonIgnore;
import in.industrend.identity.integration.ConfigClient;
import in.industrend.identity.integration.NotificationClient;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {
  public record Challenge(UUID challengeId, int expiresInSeconds, String developmentOtp) {}
  public record AuthResult(UUID customerId, String mobile, String firstName, String lastName, String email,
      boolean profileComplete, boolean pinConfigured, @JsonIgnore String sessionToken, String csrfToken,
      long expiresInSeconds) {}
  private record OtpRow(UUID id, String destination, String purpose, String hash, Instant expiresAt,
      int attempts, int maxAttempts, Instant consumedAt) {}
  private record PinRow(UUID customerId, String pinHash, int failedAttempts, Instant lockedUntil) {}

  private final JdbcClient jdbc;
  private final SecurityTokens tokens;
  private final PinHasher pins;
  private final ConfigClient config;
  private final NotificationClient notifications;
  private final boolean exposeMockOtp;

  public AuthService(JdbcClient jdbc, SecurityTokens tokens, PinHasher pins, ConfigClient config,
      NotificationClient notifications, @Value("${app.security.expose-mock-otp:false}") boolean expose) {
    this.jdbc=jdbc; this.tokens=tokens; this.pins=pins; this.config=config;
    this.notifications=notifications; this.exposeMockOtp=expose;
  }

  @Transactional
  public Challenge requestOtp(String rawMobile, String purpose, String ip) {
    var mobile=normaliseMobile(rawMobile); var p=normalisePurpose(purpose);
    if("PIN_RESET".equals(p)) {
      var exists=jdbc.sql("select count(*) from industrendindia.customers where mobile_e164=:m and status='ACTIVE' and login_pin_hash is not null").param("m",mobile).query(Integer.class).single();
      if(exists!=1) throw new IllegalArgumentException("No PIN-enabled account exists for this mobile number");
    }
    int resend=config.getInt("auth.otp.resend_seconds",45);
    var recent=jdbc.sql("select count(*) from industrendindia.otp_challenges where destination=:d and created_at>clock_timestamp()-make_interval(secs=>:s)")
        .param("d",mobile).param("s",resend).query(Integer.class).single();
    if(recent>0) throw new IllegalArgumentException("Please wait before requesting another OTP");
    int ttl=config.getInt("auth.otp.ttl_seconds",300), max=config.getInt("auth.otp.max_attempts",5);
    var otp=tokens.otp(); var id=UUID.randomUUID();
    jdbc.sql("insert into industrendindia.otp_challenges(challenge_id,destination,channel,purpose,otp_hash,expires_at,max_attempts,requested_ip) values(:id,:d,'SMS',:p,:h,clock_timestamp()+make_interval(secs=>:ttl),:max,cast(:ip as inet))")
        .param("id",id).param("d",mobile).param("p",p).param("h",tokens.hash(id+":"+otp))
        .param("ttl",ttl).param("max",max).param("ip",ip).update();
    var delivery=notifications.sendOtp(mobile,otp);
    return new Challenge(id,ttl,exposeMockOtp&&"mock".equals(delivery.provider())?otp:null);
  }

  @Transactional
  public AuthResult verify(UUID challengeId,String otp,String ip,String userAgent,UUID authenticatedCustomer) {
    var row=jdbc.sql("select challenge_id,destination,purpose,otp_hash,expires_at,attempt_count,max_attempts,consumed_at from industrendindia.otp_challenges where challenge_id=:id for update")
        .param("id",challengeId).query((rs,n)->new OtpRow(rs.getObject(1,UUID.class),rs.getString(2),rs.getString(3),rs.getString(4),rs.getTimestamp(5).toInstant(),rs.getInt(6),rs.getInt(7),rs.getTimestamp(8)==null?null:rs.getTimestamp(8).toInstant()))
        .optional().orElseThrow(()->new IllegalArgumentException("OTP challenge was not found"));
    if(row.consumedAt()!=null||row.expiresAt().isBefore(Instant.now())||row.attempts()>=row.maxAttempts()) throw new IllegalArgumentException("OTP has expired or is no longer valid");
    if(!tokens.matches(row.hash(),challengeId+":"+otp)) throw new IllegalArgumentException("Incorrect OTP");
    UUID customerId;
    if("LOGIN".equals(row.purpose())||"PIN_RESET".equals(row.purpose())) {
      customerId=jdbc.sql("select customer_id from industrendindia.customers where mobile_e164=:m and status='ACTIVE'")
          .param("m",row.destination()).query(UUID.class).optional().orElseGet(()->{ if("PIN_RESET".equals(row.purpose())) throw new IllegalArgumentException("Account was not found");
            var id=UUID.randomUUID();
            jdbc.sql("insert into industrendindia.customers(customer_id,mobile_e164,mobile_verified_at) values(:id,:m,clock_timestamp())")
                .param("id",id).param("m",row.destination()).update(); return id; });
    } else {
      if(authenticatedCustomer==null) throw new IllegalArgumentException("Sign in before verifying an account change");
      customerId=authenticatedCustomer;
    }
    jdbc.sql("update industrendindia.otp_challenges set consumed_at=clock_timestamp(),verified_at=clock_timestamp(),verified_customer_id=:c where challenge_id=:id")
        .param("c",customerId).param("id",challengeId).update();
    return createSession(customerId,ip,userAgent);
  }

  public AuthResult loginWithPin(String rawMobile, String pin, String ip, String userAgent) {
    validatePin(pin); var mobile=normaliseMobile(rawMobile);
    var row=jdbc.sql("select customer_id,login_pin_hash,pin_failed_attempts,pin_locked_until from industrendindia.customers where mobile_e164=:m and status='ACTIVE'")
        .param("m",mobile).query((rs,n)->new PinRow(rs.getObject(1,UUID.class),rs.getString(2),rs.getInt(3),toInstant(rs.getTimestamp(4))))
        .optional().orElseThrow(()->new IllegalArgumentException("Mobile number or PIN is incorrect"));
    if(row.lockedUntil()!=null&&row.lockedUntil().isAfter(Instant.now())) throw new IllegalArgumentException("PIN login is temporarily locked. Use Forgot PIN or try later");
    if(row.pinHash()==null||!pins.matches(row.pinHash(),pin)) {
      int failures=row.failedAttempts()+1;
      jdbc.sql("update industrendindia.customers set pin_failed_attempts=:f,pin_locked_until=case when :f>=5 then clock_timestamp()+interval '15 minutes' else null end where customer_id=:id")
          .param("f",failures).param("id",row.customerId()).update();
      throw new IllegalArgumentException("Mobile number or PIN is incorrect");
    }
    jdbc.sql("update industrendindia.customers set pin_failed_attempts=0,pin_locked_until=null where customer_id=:id")
        .param("id",row.customerId()).update();
    return createSession(row.customerId(),ip,userAgent);
  }

  @Transactional
  public void setPin(UUID customerId, String pin) {
    validatePin(pin);
    jdbc.sql("update industrendindia.customers set login_pin_hash=:h,pin_failed_attempts=0,pin_locked_until=null,pin_changed_at=clock_timestamp(),updated_at=clock_timestamp() where customer_id=:id")
        .param("h",pins.hash(pin)).param("id",customerId).update();
  }

  @Transactional public AuthResult current(UUID customerId,UUID sessionId) {
    var csrf=tokens.token();
    jdbc.sql("update industrendindia.customer_sessions set csrf_hash=:h,last_seen_at=clock_timestamp() where session_id=:id")
        .param("h",tokens.hash(csrf)).param("id",sessionId).update();
    return customerResult(customerId,null,csrf,0);
  }
  @Transactional public void logout(String token) {
    jdbc.sql("update industrendindia.customer_sessions set revoked_at=clock_timestamp() where token_hash=:h and revoked_at is null")
        .param("h",tokens.hash(token)).update();
  }

  private AuthResult createSession(UUID customerId,String ip,String userAgent) {
    var session=tokens.token(); var csrf=tokens.token(); var sessionId=UUID.randomUUID();
    long ttl=config.getInt("auth.session.ttl_seconds",604800);
    jdbc.sql("insert into industrendindia.customer_sessions(session_id,customer_id,token_hash,csrf_hash,user_agent_hash,ip_created,expires_at) values(:id,:c,:t,:csrf,:ua,cast(:ip as inet),clock_timestamp()+make_interval(secs=>:ttl))")
        .param("id",sessionId).param("c",customerId).param("t",tokens.hash(session)).param("csrf",tokens.hash(csrf))
        .param("ua",tokens.hash(userAgent==null?"":userAgent)).param("ip",ip).param("ttl",ttl).update();
    return customerResult(customerId,session,csrf,ttl);
  }
  private AuthResult customerResult(UUID id,String session,String csrf,long ttl) {
    return jdbc.sql("select mobile_e164,first_name,last_name,email,profile_completed_at is not null,login_pin_hash is not null from industrendindia.customers where customer_id=:id")
        .param("id",id).query((rs,n)->new AuthResult(id,rs.getString(1),rs.getString(2),rs.getString(3),rs.getString(4),rs.getBoolean(5),rs.getBoolean(6),session,csrf,ttl)).single();
  }
  private void validatePin(String pin) { if(pin==null||!pin.matches("[0-9]{6}")) throw new IllegalArgumentException("Login PIN must be exactly 6 digits"); }
  private Instant toInstant(Timestamp value) { return value==null?null:value.toInstant(); }
  public static String normaliseMobile(String raw) { var d=raw==null?"":raw.replaceAll("\\D",""); if(d.startsWith("91")&&d.length()==12)d=d.substring(2); if(!d.matches("[6-9][0-9]{9}"))throw new IllegalArgumentException("Enter a valid 10-digit Indian mobile number"); return "+91"+d; }
  private String normalisePurpose(String p) { var v=p==null?"LOGIN":p.toUpperCase(); if(!java.util.Set.of("LOGIN","PIN_RESET","MOBILE_CHANGE","EMAIL_CHANGE").contains(v))throw new IllegalArgumentException("Invalid OTP purpose"); return v; }
}
