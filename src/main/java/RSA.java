import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.security.*;

public class RSA {

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private ObjectOutputStream out;
    private ObjectInputStream in;
    private PublicKey receiverPublicRSAKey;
    private BigInteger privateSharedDHKey;
    private int sizeKey;

    public RSA(int sizeKey) throws NoSuchAlgorithmException {
        generateKeyPair( );
        this.sizeKey = sizeKey;
    }

    private void generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance( "RSA" );
        keyPairGenerator.initialize( sizeKey );
        KeyPair keyPair = keyPairGenerator.generateKeyPair( );
        this.privateKey = keyPair.getPrivate( );
        this.publicKey = keyPair.getPublic( );
    }

    public byte[] encrypt ( byte[] message ) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance( "RSA" );
        cipher.init( Cipher.ENCRYPT_MODE , publicKey );
        return cipher.doFinal( message );
    }

    public byte[] decrypt ( byte[] message , PublicKey publicKey ) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance( "RSA" );
        cipher.init( Cipher.DECRYPT_MODE , privateKey );
        return cipher.doFinal( message );
    }

    public PublicKey getPublicKey () {
        return publicKey;
    }


    public void rsaKeyDistribution () throws IOException, ClassNotFoundException {
        // Sends the public key
        sendPublicRSAKey( );
        // Receive the public key of the sender
        receivePublicRSAKey( );
    }

    public void sendPublicRSAKey () throws IOException {
        out.writeObject( getPublicKey() );
        out.flush( );
    }

    public void receivePublicRSAKey () throws IOException, ClassNotFoundException {
        receiverPublicRSAKey = (PublicKey) in.readObject();
    }

    public BigInteger agreeOnSharedPrivateDHKey (ObjectInputStream in , ObjectOutputStream out ) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        // Generates a private key
        BigInteger privateDHKey = DiffieHellman.generatePrivateKey( );
        BigInteger publicDHKey = DiffieHellman.generatePublicKey( privateDHKey );
        // Sends the public key to the server
        sendPublicDHKey( publicDHKey );
        // Waits for the server to send his public key
        byte[] clientPublicDHKeyEncrypted = (byte[]) in.readObject( );
        byte[] clientPublicDHKey = this.decrypt( clientPublicDHKeyEncrypted , receiverPublicRSAKey );
        // Generates the common private key
        //DiffieHellman diffieHellman = new DiffieHellman( getKeySizeUser( ) );
        return DiffieHellman.computePrivateKey( new BigInteger( clientPublicDHKey ) , privateDHKey );
    }

    public void sendPublicDHKey ( BigInteger publicDHKey ) throws IOException {
        out.writeObject( publicDHKey );
        out.flush( );
    }

    public void sendRequest ( String message , ObjectOutputStream out ) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, ClassNotFoundException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        // Computes the shared private key
        privateSharedDHKey = agreeOnSharedPrivateDHKey( in , out );
        byte[] messageInBytes = message.getBytes( );
        out.writeObject( this.encrypt( messageInBytes ) );
        out.flush( );
    }


}
