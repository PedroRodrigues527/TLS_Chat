import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class DiffieHellman {

    public static BigInteger generatePublicKey ( BigInteger G, BigInteger N, BigInteger privateKey ) {
        return G.modPow( privateKey , N );
    }

    public static BigInteger generateSecretKey ( BigInteger N, BigInteger publicKey , BigInteger privateKey ) {
        return publicKey.modPow( privateKey , N );
    }

}
