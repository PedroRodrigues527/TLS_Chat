import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
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

        out = new ObjectOutputStream( client.getOutputStream( ) );
        in = new ObjectInputStream( client.getInputStream( ) );

        //HELLO handshake
        helloHandShake( );

        //OK handshake
        okHandShake( );

        if(hashUser.equals("none")) {
            byte[] encryptedMessageReceivedOK = (byte[]) in.readObject();
            byte[] decryptedMessageReceivedOK = new byte[0];
            decryptedMessageReceivedOK = decryptMessageOkReceive(decryptedMessageReceivedOK, encryptedMessageReceivedOK);

            String messageDecryptS = new String(decryptedMessageReceivedOK, StandardCharsets.UTF_8);
            if (messageDecryptS.equals(userName)) {
                System.out.println("SERVER_OK");
            }
        }
        else {
            ArrayList<Object> encryptedNamePlusHash = (ArrayList<Object>) in.readObject();
            byte[] encryptedMessageReceivedOK = (byte[]) encryptedNamePlusHash.get(0);
            byte[] hashReceivedOK = (byte[]) encryptedNamePlusHash.get(1);
            byte[] decryptedMessageReceivedOK = new byte[0];
            decryptedMessageReceivedOK = decryptMessageOkReceive(decryptedMessageReceivedOK, encryptedMessageReceivedOK);

            String messageDecryptS = new String(decryptedMessageReceivedOK, StandardCharsets.UTF_8);
            String hashAlgo = "Hmac" + hashUser;
            byte[] hmacHashResult = new byte[0];
            if (encryptionUser.equals("RSA")) {
                hmacHashResult = HMac.hmacWithJava(hashAlgo, messageDecryptS, Base64.getEncoder().encodeToString(publicServerKey.getEncoded()));
            } else if (encryptionUser.equals("AES") || encryptionUser.equals("DES") || encryptionUser.equals("TripleDES")) {
                hmacHashResult = HMac.hmacWithJava(hashAlgo, messageDecryptS, Base64.getEncoder().encodeToString(symmetricKey.getBytes()));
            }
            if (Arrays.equals(hmacHashResult, hashReceivedOK)) {
                System.out.println("SERVER_OK");
            }
        }

        //Announcement message
        out.writeObject( "O cliente '" + userName + "' ligou-se ao Chat." );
        System.out.println( "Agora já pode enviar mensagens no Chat." );
    }

    public void helloHandShake () throws IOException, ClassNotFoundException {
        ArrayList<Object> cipherSuite = new ArrayList<>(4);
        cipherSuite.add( userName );
        cipherSuite.add( encryptionUser );
        cipherSuite.add( keySizeUser );
        cipherSuite.add( hashUser );
        out.writeObject( cipherSuite );

        if ( encryptionUser.equals( "AES" ) || encryptionUser.equals( "DES" )|| encryptionUser.equals( "TripleDES" ) ) {
            symmetricKey = (String) in.readObject( );
        }
        else if ( encryptionUser.equals( "RSA" ) ) {
            publicServerKey = ( PublicKey ) in.readObject( );
        }
        System.out.println( "SERVER_HELLO" );
    }

    public void okHandShake ( ) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException {
        byte[] encryptedUserName;
        String hashAlgo = "Hmac" + hashUser;
        if ( encryptionUser.equals( "RSA" ) ) {
            RSA rsa = new RSA();
            ArrayList<Object> keyList = rsa.generateKeyPair(keySizeUser);
            this.privateKey = (PrivateKey) keyList.get( 0 );
            this.publicKey = (PublicKey) keyList.get( 1 );
            encryptedUserName = RSA.encrypt( userName.getBytes( StandardCharsets.UTF_8 ) , publicServerKey );
            ArrayList<Object> encryptedPlusPublicKey = new ArrayList<>(3);
            encryptedPlusPublicKey.add( encryptedUserName );
            encryptedPlusPublicKey.add( publicKey );
            if( !hashUser.equals("none") )
            {
                encryptedPlusPublicKey.add( HMac.hmacWithJava(hashAlgo, userName, Base64.getEncoder().encodeToString(publicKey.getEncoded())));
            }
            out.writeObject( encryptedPlusPublicKey );
        }
        else if ( encryptionUser.equals( "AES" ) || encryptionUser.equals( "DES" ) || encryptionUser.equals( "TripleDES" ) ) {
            encryptedUserName = SymmetricAlgorithm.encrypt(userName.getBytes(StandardCharsets.UTF_8), symmetricKey, encryptionUser);
            if( hashUser.equals("none")) {
                out.writeObject(encryptedUserName);
            }
            else
            {
                ArrayList<Object> encryptedNamePlusHash = new ArrayList<>(2);
                encryptedNamePlusHash.add( encryptedUserName );
                encryptedNamePlusHash.add( HMac.hmacWithJava(hashAlgo, userName, Base64.getEncoder().encodeToString(symmetricKey.getBytes())));
                out.writeObject( encryptedNamePlusHash );
            }
        }
    }

    public byte[] decryptMessageOkReceive ( byte[] decryptedMessage , byte[] encryptedMessage ) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException {
        if( encryptionUser.equals( "AES" ) || encryptionUser.equals( "DES" ) || encryptionUser.equals( "TripleDES" ) ) {
            decryptedMessage = SymmetricAlgorithm.decrypt(encryptedMessage , symmetricKey, encryptionUser);
        }
        else if(encryptionUser.equals( "RSA" ) )
        {
            decryptedMessage = RSA.decrypt( encryptedMessage , privateKey );
        }
        return decryptedMessage;
    }

    public void sendMessages ( ) throws IOException {
        while ( client.isConnected( ) ) {
            Scanner usrInput = new Scanner( System.in );
            String message = usrInput.nextLine( );
            byte[] messageByte = new byte[0];
            try {
                if( hashUser.equals("none")) {
                    if (encryptionUser.equals("RSA")) {
                        messageByte = RSA.encrypt(message.getBytes(StandardCharsets.UTF_8), publicServerKey);
                    } else if (encryptionUser.equals("AES") || encryptionUser.equals("DES") || encryptionUser.equals("TripleDES")) {
                        messageByte = SymmetricAlgorithm.encrypt(message.getBytes(StandardCharsets.UTF_8), symmetricKey, encryptionUser);
                    }
                    out.writeObject( messageByte );
                }
                else
                {
                    String hashAlgo = "Hmac" + hashUser;
                    if (encryptionUser.equals("RSA")) {
                        messageByte = RSA.encrypt(message.getBytes(StandardCharsets.UTF_8), publicServerKey);
                        ArrayList<Object> encryptedTextPlusHash = new ArrayList<>(2);
                        encryptedTextPlusHash.add( messageByte );
                        encryptedTextPlusHash.add( HMac.hmacWithJava(hashAlgo, message, Base64.getEncoder().encodeToString(publicServerKey.getEncoded())));
                        out.writeObject( encryptedTextPlusHash );
                    } else if (encryptionUser.equals("AES") || encryptionUser.equals("DES") || encryptionUser.equals("TripleDES")) {
                        messageByte = SymmetricAlgorithm.encrypt(message.getBytes(StandardCharsets.UTF_8), symmetricKey, encryptionUser);
                        ArrayList<Object> encryptedTextPlusHash = new ArrayList<>(2);
                        encryptedTextPlusHash.add( messageByte );
                        encryptedTextPlusHash.add( HMac.hmacWithJava(hashAlgo, message, Base64.getEncoder().encodeToString(symmetricKey.getBytes())));
                        out.writeObject( encryptedTextPlusHash );
                    }
                }
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

                    byte[] hashReceived = new byte[0];
                    if(!hashUser.equals("none"))
                    {
                        hashReceived = (byte[]) messageWithUserName.get( 2 );
                    }

                    if ( encryptionUser.equals( "AES" ) || encryptionUser.equals( "DES" ) || encryptionUser.equals( "TripleDES" ) )
                    {
                        messageEncrypted = SymmetricAlgorithm.decrypt( messageEncrypted , symmetricKey, encryptionUser );
                    }
                    else if ( encryptionUser.equals( "RSA" ) )
                    {
                        messageEncrypted = RSA.decrypt( messageEncrypted , privateKey );
                    }

                    String messageDecrypted = new String( messageEncrypted , StandardCharsets.UTF_8 );
                    if(!hashUser.equals("none"))
                    {
                        byte[] hashResult = new byte[0];
                        if ( encryptionUser.equals( "AES" ) || encryptionUser.equals( "DES" ) || encryptionUser.equals( "TripleDES" ) )
                        {
                            hashResult = HMac.hmacWithJava("Hmac" + hashUser, messageDecrypted, Base64.getEncoder().encodeToString(symmetricKey.getBytes()));
                        }
                        else if ( encryptionUser.equals( "RSA" ) )
                        {
                            hashResult = HMac.hmacWithJava("Hmac" + hashUser, messageDecrypted, Base64.getEncoder().encodeToString(publicKey.getEncoded()));
                        }

                        if (Arrays.equals(hashResult, hashReceived)) {
                            System.out.println(userName + ": " + messageDecrypted);
                        }
                        else
                        {
                            System.out.println("-- INVALID MESSAGE RECEIVED --");
                        }
                    }
                    else {
                        System.out.println(userName + ": " + messageDecrypted);
                    }
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
