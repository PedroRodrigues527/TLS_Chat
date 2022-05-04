import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.util.ArrayList;

public class RSA {

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

    public static byte[] encrypt ( byte[] message, PublicKey publicKey ) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance( "RSA" );
        cipher.init( Cipher.ENCRYPT_MODE , publicKey );
        return cipher.doFinal( message );
    }

    public static byte[] decrypt ( byte[] message , PrivateKey privateKey ) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance( "RSA" );
        cipher.init( Cipher.DECRYPT_MODE , privateKey );
        return cipher.doFinal( message );
    }

}
