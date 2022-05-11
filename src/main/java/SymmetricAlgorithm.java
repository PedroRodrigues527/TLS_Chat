import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

/**
 * Class responsible for the implementation of the symmetric Algorithm
 */
public class SymmetricAlgorithm {

    private static final int ENCRYPT_MODE = 1;
    private static final int DECRYPT_MODE = 2;

    /**
     * Method responsible for the Encryption of the specified message, key and algorithm.
     *
     * @param text content to be encrypted
     * @param key key encode content
     * @param algorithm algorithm that user chose
     * @return sent message encrypted in bytes
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException
     */
    public static byte[] encrypt ( byte[] text , String key, String algorithm ) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        Cipher cipher = Cipher.getInstance( algorithm );
        byte[] decodedKey = Base64.getDecoder().decode(key);
        SecretKeySpec secretKeySpec = new SecretKeySpec( decodedKey, 0, decodedKey.length , algorithm );
        cipher.init( Cipher.ENCRYPT_MODE , secretKeySpec );
        ArrayList<byte[]> textSplits = splitText( text , 15 , ENCRYPT_MODE );
        ByteArrayOutputStream output = new ByteArrayOutputStream( );
        for ( byte[] textSplit : textSplits ) {
            byte[] textEncrypted = cipher.doFinal( textSplit );
            output.write( textEncrypted );
        }
        return output.toByteArray( );
    }

    /**
     * Method responsible for the Decryption of the specified message, key and algorithm.
     *
     * @param text content to be decrypted
     * @param key key decode content
     * @param algorithm algorithm that user chose
     * @return FALTA VER ISTO
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException
     */
    public static byte[] decrypt ( byte[] text , String key, String algorithm ) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        Cipher cipher = Cipher.getInstance( algorithm );
        byte[] decodedKey = Base64.getDecoder().decode(key);
        SecretKeySpec secretKeySpec = new SecretKeySpec( decodedKey , 0, decodedKey.length, algorithm );
        cipher.init( Cipher.DECRYPT_MODE , secretKeySpec );
        ArrayList<byte[]> textSplits = splitText( text , 16 , DECRYPT_MODE );
        ByteArrayOutputStream output = new ByteArrayOutputStream( );
        for ( byte[] textSplit : textSplits ) {
            output.write( cipher.doFinal( textSplit ) );
        }
        byte[] outputByte = output.toByteArray( );
        int padding = outputByte[ outputByte.length - 1 ];
        return Arrays.copyOfRange( outputByte , 0 , outputByte.length - padding );
    }

    /**
     * Method responsible for the implementation of the Split text.
     *
     * @param text encrypted
     * @param blockSize size of the block
     * @param mode mode (encrypt mode or decrypted mode)
     * @return text divided
     * @throws IOException
     */
    private static ArrayList<byte[]> splitText ( byte[] text , int blockSize , int mode ) throws IOException {
        ArrayList<byte[]> textSplits = new ArrayList<>( );
        for ( int startPos = 0; startPos < text.length; startPos += blockSize ) {
            int endPos = startPos + blockSize;
            if ( endPos > text.length ) {
                endPos = text.length;
            }
            textSplits.add( Arrays.copyOfRange( text , startPos , endPos ) );
        }
        if ( mode == ENCRYPT_MODE ) {
            byte[] lastBlock = textSplits.get( textSplits.size( ) - 1 );
            int padding = blockSize - lastBlock.length;
            ByteArrayOutputStream output = new ByteArrayOutputStream( );
            if ( padding == 0 ) {
                for ( int i = 0; i < blockSize; i++ ) {
                    output.write( (byte) blockSize );
                }
                textSplits.add( output.toByteArray( ) );
            } else {
                output.write( lastBlock );
                for ( int i = 0; i < padding; i++ ) {
                    output.write( (byte) padding );
                }
                textSplits.set( textSplits.size( ) - 1 , output.toByteArray( ) );
            }
        }
        return textSplits;
    }

    /**
     * Method responsible for the Generation of a symmetric key
     *
     * @param sizeKey size of the key
     * @param algorithm algorithm in use
     * @return FALTA VER
     * @throws NoSuchAlgorithmException
     */
    public String generateKey(int sizeKey, String algorithm) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance( algorithm );
        keyGenerator.init( sizeKey );
        SecretKey key = keyGenerator.generateKey( );
        // get base64 encoded version of the key: https://stackoverflow.com/questions/5355466/converting-secret-key-into-a-string-and-vice-versa
        return Base64.getEncoder().encodeToString( key.getEncoded( ) );
    }

}