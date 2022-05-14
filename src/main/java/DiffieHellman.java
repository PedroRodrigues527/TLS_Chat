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
     * @param G Specified Integer that prevents Overflow
     * @param N Specified Integer that prevents Overflow
     * @param privateKey Specified Integer for the Private key that prevents Overflow
     * @return public key of DiffieHellman
     */
    public static BigInteger generatePublicKey ( BigInteger G, BigInteger N, BigInteger privateKey ) {
        return G.modPow( privateKey , N );
    }

    /**
     * Method that creates a DiffieHellman Private Key
     *
     * @param N Specified Integer that prevents Overflow
     * @param publicKey Specified Integer for public key that prevents Overflow
     * @param privateKey Specified Integer for private key that prevents Overflow
     * @return private key of DiffieHellman
     */
    public static BigInteger generateSecretKey ( BigInteger N, BigInteger publicKey , BigInteger privateKey ) {
        return publicKey.modPow( privateKey , N );
    }

}
