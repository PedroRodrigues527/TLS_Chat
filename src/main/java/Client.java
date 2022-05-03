import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Scanner;

public class Client {

    private final Socket client;
    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private RSA rsa; //Final -> might not be initialized - ver!
    private PublicKey receiverPublicRSAKey;
    private BigInteger privateSharedDHKey;
    private final String userName, encryptionUser, hashUser;
    private final int keySizeUser;

    public Client ( String host , int port , String userName, String encryptionUser, int keySizeUser, String hashUser ) throws IOException, ClassNotFoundException, NoSuchAlgorithmException {
        client = new Socket( host , port );
        this.userName = userName;
        this.encryptionUser = encryptionUser;
        this.keySizeUser = keySizeUser;
        this.hashUser = hashUser;

        if ( encryptionUser.equals( "RSA" ) ) {
            rsa = new RSA( keySizeUser );
            rsaKeyDistribution();
        }

        out = new ObjectOutputStream(client.getOutputStream());
        in = new ObjectInputStream(client.getInputStream());



        //HELLO handshake
        out.writeObject( userName );
        if(userName.equals(in.readObject( )))
        {
            System.out.println("SERVER_HELLO");
        }

        //OK handshake


        //Announcement message
        out.writeObject("O cliente '" + userName + "' ligou-se ao Chat.");
        System.out.println("Agora já pode enviar mensagens no chat.");
    }

    public String getEncryptionUser() {
        return encryptionUser;
    }

    public String getHashUser() {
        return hashUser;
    }

    public int getKeySizeUser() {
        return keySizeUser;
    }


    /*******************************RSA METHODS*********************************************************************************************************************************************/

    private void rsaKeyDistribution () throws IOException, ClassNotFoundException {
        // Sends the public key
        sendPublicRSAKey( );
        // Receive the public key of the sender
        receivePublicRSAKey( );
    }

    private void sendPublicRSAKey () throws IOException {
        out.writeObject( rsa.getPublicKey() );
        out.flush( );
    }

    private void receivePublicRSAKey () throws IOException, ClassNotFoundException {
        receiverPublicRSAKey = (PublicKey) in.readObject();
    }

    private BigInteger agreeOnSharedPrivateDHKey ( ObjectInputStream in , ObjectOutputStream out ) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        // Generates a private key
        BigInteger privateDHKey = DiffieHellman.generatePrivateKey( );
        BigInteger publicDHKey = DiffieHellman.generatePublicKey( privateDHKey );
        // Sends the public key to the server
        sendPublicDHKey( publicDHKey );
        // Waits for the server to send his public key
        byte[] clientPublicDHKeyEncrypted = (byte[]) in.readObject( );
        byte[] clientPublicDHKey = rsa.decrypt( clientPublicDHKeyEncrypted , receiverPublicRSAKey );
        // Generates the common private key
        //DiffieHellman diffieHellman = new DiffieHellman( getKeySizeUser( ) );
        return DiffieHellman.computePrivateKey( new BigInteger( clientPublicDHKey ) , privateDHKey );
    }

    private void sendPublicDHKey ( BigInteger publicDHKey ) throws IOException {
        out.writeObject( publicDHKey );
        out.flush( );
    }

    private void sendRequest ( String message , ObjectOutputStream out ) throws IOException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, ClassNotFoundException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        // Computes the shared private key
        privateSharedDHKey = agreeOnSharedPrivateDHKey( in , out );
        byte[] messageInBytes = message.getBytes( );
        out.writeObject( rsa.encrypt( messageInBytes ) );
        out.flush( );
    }


/************************************************************************************************************************************************************************************************************************* */


    public void sendMessages () throws IOException {
        while ( client.isConnected( ) ) {
            Scanner usrInput = new Scanner( System.in );
            String message = usrInput.nextLine( );
            try {
                if ( this.encryptionUser.equals("RSA") ){
                    sendRequest( message , out );
                }
                out.writeObject( message );
            } catch ( IOException e ) {
                closeConnection( );
                break;
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            }
        }

    }

    public void readMessages () {
        new Thread( () -> {
            while ( client.isConnected( ) ) {
                try {
                    if ( this.encryptionUser.equals( "rsa" ) ) {

                    }
                    ArrayList<Object> messageWithUserName = (ArrayList<Object>) in.readObject( );
                    String userName = (String) messageWithUserName.get( 0 );
                    String messageDecrypted = new String( (byte[]) messageWithUserName.get( 1 ) );
                    System.out.println(userName + ": " + messageDecrypted);
                } catch ( IOException | ClassNotFoundException e ) {
                    try {
                        closeConnection( );
                    } catch ( IOException ex ) {
                        ex.printStackTrace( );
                    }
                    break;
                }
            }
        } ).start( );
    }

    private void closeConnection () throws IOException {
        client.close( );
        out.close( );
        in.close( );
    }

}
