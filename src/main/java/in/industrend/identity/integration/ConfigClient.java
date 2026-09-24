package in.industrend.identity.integration;
import java.net.URI; import java.net.http.*; import org.springframework.beans.factory.annotation.Value; import org.springframework.stereotype.Component;
@Component public class ConfigClient {
 private final HttpClient http=HttpClient.newHttpClient(); private final String baseUrl,token;
 public ConfigClient(@Value("${services.config.url}") String u,@Value("${services.internal-token}") String t){baseUrl=u;token=t;}
 public String get(String key,String fallback){try{var r=HttpRequest.newBuilder(URI.create(baseUrl+"/internal/v1/config/"+key)).header("X-Service-Token",token).GET().build();var x=http.send(r,HttpResponse.BodyHandlers.ofString());return x.statusCode()==200?x.body():fallback;}catch(Exception e){return fallback;}}
 public int getInt(String key,int fallback){try{return Integer.parseInt(get(key,Integer.toString(fallback)));}catch(Exception e){return fallback;}}
}
