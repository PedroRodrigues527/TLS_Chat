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
import java.security.PrivateKey;
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

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private PublicKey publicServerKey;

    public Client ( String host , int port , String userName, String encryptionUser, int keySizeUser, String hashUser ) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        client = new Socket( host , port );
        this.userName = userName;
        this.encryptionUser = encryptionUser;
        this.keySizeUser = keySizeUser;
        this.hashUser = hashUser;


        out = new ObjectOutputStream(client.getOutputStream());
        in = new ObjectInputStream(client.getInputStream());

        //HELLO handshake
        ArrayList<Object> cipherSuite = new ArrayList<>(4);
        cipherSuite.add(userName);
        cipherSuite.add(encryptionUser);
        cipherSuite.add(keySizeUser);
        cipherSuite.add(hashUser);
        out.writeObject(cipherSuite);

        if ( encryptionUser.equals( "AES" ) || encryptionUser.equals( "3DES" ) ||encryptionUser.equals( "DES" )  ) { //DES
            symmetricKey = (String) in.readObject();
        }
        else if ( encryptionUser.equals("RSA")) {
            publicServerKey = (PublicKey) in.readObject();
        }
        System.out.println("SERVER_HELLO");

        //OK handshake
        byte[] encryptedUsername = null;
        if ( encryptionUser.equals( "RSA" ) ) {
            RSA rsa = new RSA();
            ArrayList<Object> keyList = rsa.generateKeyPair(keySizeUser);
            this.privateKey = (PrivateKey) keyList.get(0);
            this.publicKey = (PublicKey) keyList.get(1);
            encryptedUsername = RSA.encrypt(userName.getBytes(StandardCharsets.UTF_8), publicServerKey);
            ArrayList<Object> encryptedPlusPublicKey = new ArrayList<>(2);
            encryptedPlusPublicKey.add(encryptedUsername);
            encryptedPlusPublicKey.add(publicKey);
            out.writeObject( encryptedPlusPublicKey );
        }
        else if ( encryptionUser.equals("AES") ) { //DES
            encryptedUsername = AES.encrypt(userName.getBytes(StandardCharsets.UTF_8), symmetricKey);
            out.writeObject( encryptedUsername );
        } else if (encryptionUser.equals( "DES" )) {
            encryptedUsername = DES.encrypt(userName.getBytes(StandardCharsets.UTF_8), symmetricKey);
            out.writeObject( encryptedUsername );
        }

        byte[] encryptedMessageReceivedOK = (byte[]) in.readObject();
        byte[] decryptedMessageReceivedOK = new byte[0];
        if(encryptionUser.equals("AES")) {
            decryptedMessageReceivedOK = AES.decrypt(encryptedMessageReceivedOK, symmetricKey);
        }
        else if(encryptionUser.equals("DES")) {
            decryptedMessageReceivedOK = DES.decrypt(encryptedMessageReceivedOK, symmetricKey);
        }
        else if(encryptionUser.equals("RSA"))
        {
            decryptedMessageReceivedOK = RSA.decrypt(encryptedMessageReceivedOK, privateKey);
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
                    messageByte = RSA.encrypt(message.getBytes(StandardCharsets.UTF_8), publicServerKey);
                }
                else if (encryptionUser.equals("AES"))
                {
                    messageByte = AES.encrypt(message.getBytes(StandardCharsets.UTF_8), symmetricKey);
                }
                else if (encryptionUser.equals("DES"))
                {
                    messageByte = DES.encrypt(message.getBytes(StandardCharsets.UTF_8), symmetricKey);
                }
                out.writeObject( messageByte );
            } catch ( IOException e ) {
                closeConnection( );
                break;
            } catch (NoSuchAlgorithmException | NoSuchPaddingException |
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
                    else if (encryptionUser.equals("DES"))
                    {
                        messageEncrypted = DES.decrypt(messageEncrypted, symmetricKey);
                    }
                    else if (encryptionUser.equals("RSA"))
                    {
                        messageEncrypted = RSA.decrypt(messageEncrypted, privateKey);
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
