import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.ArrayList;

/**
 * This class will be responsible for the implementation of the RSA Protocol.
 */
public class RSA {

    /**
     * Method that Generates the private and public key
     *
     * @param sizeKey size of the key selected
     * @return arraylist that contains public and private key
     * @throws NoSuchAlgorithmException
     */
    public ArrayList<Object> generateKeyPair(int sizeKey) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance( "RSA" );
        keyPairGenerator.initialize( sizeKey );
        KeyPair keyPair = keyPairGenerator.generateKeyPair( );
        PrivateKey privateKey = keyPair.getPrivate( );
        PublicKey publicKey = keyPair.getPublic( );
        ArrayList<Object> arrayKeyPair = new ArrayList<>(2);
        arrayKeyPair.add(privateKey);
        arrayKeyPair.add(publicKey);
        return arrayKeyPair;
    }

    /**
     * Method that Encrypts the specified message with the RSA algorithm.
     *
     * @param message message to be encrypted
     * @param publicKey key to encrypt content
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] encrypt ( byte[] message, PublicKey publicKey ) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance( "RSA" );
        cipher.init( Cipher.ENCRYPT_MODE , publicKey );
        return cipher.doFinal( message );
    }

    /**
     * Method that Decrypts the specified message with the RSA algorithm.
     *
     * @param message message to be decrypted
     * @param privateKey key to decrypt message
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public static byte[] decrypt ( byte[] message , PrivateKey privateKey ) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance( "RSA" );
        cipher.init( Cipher.DECRYPT_MODE , privateKey );
        return cipher.doFinal( message );
    }

}
