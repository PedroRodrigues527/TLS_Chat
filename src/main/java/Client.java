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
        helloHandShake( );

        //OK handshake
        byte[] encryptedUsername = null;
        okHandShake( encryptedUsername );

        byte[] encryptedMessageReceivedOK = (byte[]) in.readObject();
        byte[] decryptedMessageReceivedOK = new byte[0];
        decryptMessageOkReceive( decryptedMessageReceivedOK , encryptedMessageReceivedOK );

        String messageDecryptS = new String(decryptedMessageReceivedOK, StandardCharsets.UTF_8);
        if(messageDecryptS.equals(userName))
        {
            System.out.println("SERVER_OK");
        }

        //Announcement message
        out.writeObject("O cliente '" + userName + "' ligou-se ao Chat.");
        System.out.println("Agora já pode enviar mensagens no Chat.");
    }

    public void helloHandShake () throws IOException, ClassNotFoundException {
        ArrayList<Object> cipherSuite = new ArrayList<>(4);
        cipherSuite.add(userName);
        cipherSuite.add(encryptionUser);
        cipherSuite.add(keySizeUser);
        cipherSuite.add(hashUser);
        out.writeObject(cipherSuite);

        if ( encryptionUser.equals( "AES" ) || encryptionUser.equals( "DES" )||encryptionUser.equals( "TripleDES" ) ) { //DES
            symmetricKey = (String) in.readObject();
        }
        else if ( encryptionUser.equals("RSA")) {
            publicServerKey = (PublicKey) in.readObject();
        }
        System.out.println("SERVER_HELLO");
    }

    public byte[] decryptMessageOkReceive ( byte[] decryptedMessage , byte[] encryptedMessage ) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException {
        if(encryptionUser.equals("AES")) {
            decryptedMessage = AES.decrypt(encryptedMessage, symmetricKey);
        }
        else if(encryptionUser.equals("DES")) {
            decryptedMessage = DES.decrypt(encryptedMessage, symmetricKey);
        }
        else if(encryptionUser.equals("TripleDES")) {
            decryptedMessage = TripleDES.decrypt(encryptedMessage, symmetricKey);
        }
        else if(encryptionUser.equals("RSA"))
        {
            decryptedMessage = RSA.decrypt(encryptedMessage, privateKey);
        }
        return decryptedMessage;
    }

    public void okHandShake ( byte[] encryptedUserName ) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException {
        if ( encryptionUser.equals( "RSA" ) ) {
            RSA rsa = new RSA();
            ArrayList<Object> keyList = rsa.generateKeyPair(keySizeUser);
            this.privateKey = (PrivateKey) keyList.get(0);
            this.publicKey = (PublicKey) keyList.get(1);
            encryptedUserName = RSA.encrypt(userName.getBytes(StandardCharsets.UTF_8), publicServerKey);
            ArrayList<Object> encryptedPlusPublicKey = new ArrayList<>(2);
            encryptedPlusPublicKey.add(encryptedUserName);
            encryptedPlusPublicKey.add(publicKey);
            out.writeObject( encryptedPlusPublicKey );
        }
        else if ( encryptionUser.equals("AES") ) { //DES
            encryptedUserName = AES.encrypt(userName.getBytes(StandardCharsets.UTF_8), symmetricKey);
            out.writeObject( encryptedUserName );
        }
        else if ( encryptionUser.equals( "DES" ) ) { //DES
            encryptedUserName = DES.encrypt(userName.getBytes(StandardCharsets.UTF_8), symmetricKey);
            out.writeObject( encryptedUserName );
        }
        else if ( encryptionUser.equals( "TripleDES" ) ) {
            encryptedUserName = TripleDES.encrypt(userName.getBytes(StandardCharsets.UTF_8), symmetricKey);
            out.writeObject( encryptedUserName );
        }
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
                else if (encryptionUser.equals("TripleDES"))
                {
                    messageByte = TripleDES.encrypt(message.getBytes(StandardCharsets.UTF_8), symmetricKey);
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
                    else if (encryptionUser.equals("TripleDES"))
                    {
                        messageEncrypted = TripleDES.decrypt(messageEncrypted, symmetricKey);
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
