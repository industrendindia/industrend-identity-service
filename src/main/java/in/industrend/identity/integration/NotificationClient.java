package in.industrend.identity.integration;
import com.fasterxml.jackson.databind.ObjectMapper; import java.net.URI; import java.net.http.*; import java.util.Map; import org.springframework.beans.factory.annotation.Value; import org.springframework.stereotype.Component;
@Component public class NotificationClient {
 public record Delivery(String provider,String messageId,String status){}
 private final HttpClient http=HttpClient.newHttpClient(); private final ObjectMapper json; private final String baseUrl,token;
 public NotificationClient(ObjectMapper j,@Value("${services.notification.url}") String u,@Value("${services.internal-token}") String t){json=j;baseUrl=u;token=t;}
 public Delivery sendOtp(String mobile,String otp){try{var body=json.writeValueAsString(Map.of("mobile",mobile,"otp",otp,"templateKey","customer_otp"));var r=HttpRequest.newBuilder(URI.create(baseUrl+"/internal/v1/notifications/otp")).header("Content-Type","application/json").header("X-Service-Token",token).POST(HttpRequest.BodyPublishers.ofString(body)).build();var x=http.send(r,HttpResponse.BodyHandlers.ofString());if(x.statusCode()/100!=2)throw new IllegalStateException("Notification service rejected OTP");return json.readValue(x.body(),Delivery.class);}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException("OTP delivery interrupted",e);}catch(Exception e){throw new IllegalStateException("OTP delivery failed",e);}}
}
