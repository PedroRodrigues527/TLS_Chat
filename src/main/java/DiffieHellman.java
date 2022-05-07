import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class DiffieHellman {
    //private static final int NUM_BITS = 128;

    /*public static BigInteger generatePrivateKey () throws NoSuchAlgorithmException {
        Random randomGenerator = SecureRandom.getInstance( "SHA1PRNG" );
        return new BigInteger( NUM_BITS , randomGenerator );
    }*/

    public static BigInteger generatePublicKey ( BigInteger G, BigInteger N, BigInteger privateKey ) {
        return G.modPow( privateKey , N );
    }

    public static BigInteger generateSecretKey ( BigInteger N, BigInteger publicKey , BigInteger privateKey ) {
        return publicKey.modPow( privateKey , N );
    }

}
