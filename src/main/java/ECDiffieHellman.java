import javax.crypto.KeyAgreement;
import java.security.*;

/**
 * Class responsible for the key Generator methods
 */
//FONTE: https://neilmadden.blog/2016/05/20/ephemeral-elliptic-curve-diffie-hellman-key-agreement-in-java/
public class ECDiffieHellman {

    /**
     * Method responsible for the pair of keys creation
     *
     * @return
     * @throws NoSuchAlgorithmException
     */
    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        // Generate ECDH keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    /**
     * Getter for Public key
     *
     * @param kp value for KeyPair is received
     * @return
     */
    public PublicKey getPublicKey(KeyPair kp)
    {
        return kp.getPublic();
    }

    /**
     * Getter for Private key
     *
     * @param kp value for KeyPair is received
     * @return
     */
    public PrivateKey getPrivateKey(KeyPair kp)
    {
        return kp.getPrivate();
    }

    /**
     * Method on the receiver-end for the Secret Key.
     *
     * @param privateKey Value attributed for the private key
     * @param otherPublicKey value for PublicKey is received
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     */
    public byte[] getSecretKey(PrivateKey privateKey, PublicKey otherPublicKey) throws InvalidKeyException, NoSuchAlgorithmException {
        // Perform key agreement
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(privateKey);
        ka.doPhase(otherPublicKey, true);

        // Get shared secret
        return ka.generateSecret();
    }


}
