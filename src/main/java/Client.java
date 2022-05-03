import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Scanner;

public class Client {

    private final Socket client;
    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private final String userName, encryptionUser, hashUser;
    private final int keySizeUser;

    private String symmetricKey;

    private RSA rsa; //Final -> might not be initialized - ver!
    private PublicKey receiverPublicRSAKey;
    private BigInteger privateSharedDHKey;

    public Client ( String host , int port , String userName, String encryptionUser, int keySizeUser, String hashUser ) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        client = new Socket( host , port );
        this.userName = userName;
        this.encryptionUser = encryptionUser;
        this.keySizeUser = keySizeUser;
        this.hashUser = hashUser;

        if ( encryptionUser.equals( "RSA" ) ) {
            rsa = new RSA( keySizeUser );
            rsa.rsaKeyDistribution();
        }

        out = new ObjectOutputStream(client.getOutputStream());
        in = new ObjectInputStream(client.getInputStream());

        //HELLO handshake
        ArrayList<Object> cipherSuite = new ArrayList<>(4);
        cipherSuite.add(userName);
        cipherSuite.add(encryptionUser);
        cipherSuite.add(keySizeUser);
        cipherSuite.add(hashUser);
        out.writeObject(cipherSuite);

        if ( encryptionUser.equals( "AES" ) ) {
            symmetricKey = (String) in.readObject();
            System.out.println("SERVER_HELLO");
        }

        //OK handshake
        byte[] encryptedUsername = null;
        if ( encryptionUser.equals( "RSA" ) ) {

        }
        else if ( encryptionUser.equals("AES") ) {
            encryptedUsername = AES.encrypt(userName.getBytes(StandardCharsets.UTF_8), symmetricKey);
        }
        out.writeObject( encryptedUsername );

        byte[] encryptedMessageReceivedOK = (byte[]) in.readObject();
        byte[] decryptedMessageReceivedOK = new byte[0];
        if(encryptionUser.equals("AES")) {
            decryptedMessageReceivedOK = AES.decrypt(encryptedMessageReceivedOK, symmetricKey);
        }

        String messageDecryptS = new String(decryptedMessageReceivedOK, StandardCharsets.UTF_8);
        if(messageDecryptS.equals(userName))
        {
            System.out.println("SERVER_OK");
        }

        //Announcement message
        out.writeObject("O cliente '" + userName + "' ligou-se ao Chat.");
        System.out.println("Agora já pode enviar mensagens no Chat.");
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

    public String getSymmetricKey() {
        return symmetricKey;
    }

    public void sendMessages () throws IOException {
        while ( client.isConnected( ) ) {
            Scanner usrInput = new Scanner( System.in );
            String message = usrInput.nextLine( );
            byte[] messageByte = new byte[0];
            try {
                if ( encryptionUser.equals("RSA") ){
                    rsa.sendRequest( message , out );
                }
                else if (encryptionUser.equals("AES"))
                {
                    messageByte = AES.encrypt(message.getBytes(StandardCharsets.UTF_8), symmetricKey);
                }
                out.writeObject( messageByte );
            } catch ( IOException e ) {
                closeConnection( );
                break;
            } catch (NoSuchAlgorithmException | ClassNotFoundException | NoSuchPaddingException |
                     IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
                e.printStackTrace();
            }
        }

    }

    public void readMessages () {
        new Thread( () -> {
            while ( client.isConnected( ) ) {
                try {
                    ArrayList<Object> messageWithUserName = (ArrayList<Object>) in.readObject( );
                    String userName = (String) messageWithUserName.get( 0 );
                    byte[] messageEncrypted = (byte[]) messageWithUserName.get( 1 );
                    if (encryptionUser.equals("AES"))
                    {
                        messageEncrypted = AES.decrypt(messageEncrypted, symmetricKey);
                    }
                    String messageDecrypted = new String(messageEncrypted, StandardCharsets.UTF_8);
                    System.out.println(userName + ": " + messageDecrypted);
                } catch ( IOException | ClassNotFoundException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
                          BadPaddingException | InvalidKeyException e ) {
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
