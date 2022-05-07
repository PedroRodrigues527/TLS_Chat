import javax.crypto.KeyAgreement;
import java.security.*;

//FONTE: https://neilmadden.blog/2016/05/20/ephemeral-elliptic-curve-diffie-hellman-key-agreement-in-java/
public class ECDiffieHellman {

    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        // Generate ephemeral ECDH keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        return kpg.generateKeyPair();
    }

    public PublicKey getPublicKey(KeyPair kp)
    {
        return kp.getPublic();
    }

    public PrivateKey getPrivateKey(KeyPair kp)
    {
        return kp.getPrivate();
    }

    public byte[] getSecretKey(PrivateKey privateKey, PublicKey otherPublicKey) throws InvalidKeyException, NoSuchAlgorithmException {
        // Perform key agreement
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(privateKey);
        ka.doPhase(otherPublicKey, true);

        // Get shared secret
        return ka.generateSecret();
    }


}
