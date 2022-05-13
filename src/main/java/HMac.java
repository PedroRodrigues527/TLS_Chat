import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Class that is responsible for the Hashed Message Authentication Code
 */
public class HMac {

    /**
     * Method that implements the Hashed Message Authentication Code based on Java
     *
     * @param algorithm String with specified algorithm input
     * @param data String with specified data input
     * @param key String with specified key input
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    //FONTE: https://www.baeldung.com/java-hmac
    public static byte[] hmacWithJava(String algorithm, String data, String key)
            throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), algorithm);
        Mac mac = Mac.getInstance( algorithm );
        mac.init( secretKeySpec );
        return mac.doFinal( data.getBytes( ) );
    }

}
