import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

/**
 * Class responsible for the key Generator methods
 */
public class DiffieHellman {

    /**
     * Method that creates a DiffieHellman Public Key
     *
     * @param G
     * @param N
     * @param privateKey
     * @return
     */
    public static BigInteger generatePublicKey ( BigInteger G, BigInteger N, BigInteger privateKey ) {
        return G.modPow( privateKey , N );
    }

    /**
     * Method that creates a DiffieHellman Private Key
     *
     * @param N
     * @param publicKey
     * @param privateKey
     * @return
     */
    public static BigInteger generateSecretKey ( BigInteger N, BigInteger publicKey , BigInteger privateKey ) {
        return publicKey.modPow( privateKey , N );
    }

}
