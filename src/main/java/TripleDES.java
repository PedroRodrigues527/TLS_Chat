import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

public class TripleDES {

    private static final int ENCRYPT_MODE = 1;
    private static final int DECRYPT_MODE = 2;

    public static byte[] encrypt ( byte[] text , String key ) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        Cipher cipher = Cipher.getInstance( "TripleDES" );
        byte[] decodedKey = Base64.getDecoder().decode(key);
        SecretKeySpec secretKeySpec = new SecretKeySpec( decodedKey, 0, decodedKey.length,"TripleDES" );
        cipher.init( Cipher.ENCRYPT_MODE , secretKeySpec );
        ArrayList<byte[]> textSplits = splitText( text , 15 , ENCRYPT_MODE );
        ByteArrayOutputStream output = new ByteArrayOutputStream( );
        for ( byte[] textSplit : textSplits ) {
            byte[] textEncrypted = cipher.doFinal( textSplit );
            output.write( textEncrypted );
        }
        return output.toByteArray( );
    }

    public static byte[] decrypt ( byte[] text , String key ) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        Cipher cipher = Cipher.getInstance( "TripleDES" );
        byte[] decodedKey = Base64.getDecoder().decode(key);
        SecretKeySpec secretKeySpec = new SecretKeySpec( decodedKey , 0, decodedKey.length,"TripleDES" );
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

    public String generateKey(int sizeKey) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance( "TripleDES" );
        keyGenerator.init( sizeKey );
        SecretKey key = keyGenerator.generateKey( );
        // get base64 encoded version of the key: https://stackoverflow.com/questions/5355466/converting-secret-key-into-a-string-and-vice-versa
        return Base64.getEncoder( ).encodeToString( key.getEncoded( ) );
    }

}