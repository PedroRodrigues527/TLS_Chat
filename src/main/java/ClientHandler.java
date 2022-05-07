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
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

public class ClientHandler implements Runnable {

    public static final ArrayList<ClientHandler> clientHandlers = new ArrayList<>( );
    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private final String userName;
    private final Socket server;

    private final String encUser;
    private final int sizeKeyUser;
    private final String hashUser;

    private final String keyExchangeUser;

    private String symmetricKey;

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private PublicKey publicClientKey;

    public ClientHandler ( Socket server ) throws Exception {
        this.server = server;
        this.in = new ObjectInputStream( server.getInputStream( ) );
        this.out = new ObjectOutputStream( server.getOutputStream( ) );

        //HELLO handshake
        ArrayList<Object> clientHello = (ArrayList<Object>) in.readObject( );
        this.userName = (String) clientHello.get( 0 );
        this.encUser = (String) clientHello.get( 1 );
        this.sizeKeyUser = (int) clientHello.get( 2 );
        this.hashUser = (String) clientHello.get( 3 );
        this.keyExchangeUser = (String) clientHello.get( 4 );
        System.out.println( "CLIENT_HELLO" );

        boolean b = encUser.equals("AES") || encUser.equals("DES") || encUser.equals("TripleDES");
        helloHandShakeSend(b);


        //OK handshake
        String hashAlgo = "Hmac" + hashUser;
        ArrayList<Object> messagePlusHash = OkHandShakeReceived(b);
        byte[] decryptedMessageReceivedOK = (byte[]) messagePlusHash.get(0);
        byte[] hmacHash = (byte[]) messagePlusHash.get(1);

        String messageDecryptS = new String(decryptedMessageReceivedOK, StandardCharsets.UTF_8);
        OkHandShakeSend(b, hashAlgo, messageDecryptS, hmacHash, decryptedMessageReceivedOK);

        //Announcement message
        clientHandlers.add( this );
        String announcement = (String) in.readObject( );
        broadcastMessage( announcement.getBytes( ), true);
    }

    public void helloHandShakeSend (boolean b) throws IOException, NoSuchAlgorithmException {
        if(b)
        {
            SymmetricAlgorithm sa = new SymmetricAlgorithm();
            this.symmetricKey = sa.generateKey( sizeKeyUser, encUser );
            out.writeObject( symmetricKey );
        }
        else if( encUser.equals( "RSA" ) )
        {
            RSA rsa = new RSA();
            ArrayList<Object> keyList = rsa.generateKeyPair( sizeKeyUser );
            this.privateKey = ( PrivateKey ) keyList.get( 0 );
            this.publicKey = ( PublicKey ) keyList.get( 1 );
            out.writeObject( publicKey );
        }
    }

    public ArrayList<Object> OkHandShakeReceived(boolean b) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException, ClassNotFoundException {
        byte[] decryptedMessageReceivedOK = new byte[0];
        byte[] hmacHash = new byte[0];
        if(b) {
            if( hashUser.equals("none")) {
                byte[] encryptedMessageReceivedOK = (byte[]) in.readObject();
                decryptedMessageReceivedOK = SymmetricAlgorithm.decrypt(encryptedMessageReceivedOK, symmetricKey, encUser);
            }
            else
            {
                ArrayList<Object> encryptedMessagePlusHash = (ArrayList<Object>) in.readObject();
                byte[] encryptedMessageReceivedOK = (byte[]) encryptedMessagePlusHash.get(0);
                hmacHash = (byte[]) encryptedMessagePlusHash.get(1);
                decryptedMessageReceivedOK = SymmetricAlgorithm.decrypt(encryptedMessageReceivedOK, symmetricKey, encUser);
            }
        }
        else if(encUser.equals("RSA"))
        {
            ArrayList<Object> encryptedPlusPublicKey = (ArrayList<Object>) in.readObject();
            byte[] encryptedMessageUser = (byte[]) encryptedPlusPublicKey.get( 0 );
            this.publicClientKey = (PublicKey) encryptedPlusPublicKey.get( 1 );
            if( !hashUser.equals("none"))
            {
                hmacHash = (byte[]) encryptedPlusPublicKey.get(2);
            }
            decryptedMessageReceivedOK = RSA.decrypt( encryptedMessageUser , privateKey );
        }

        ArrayList<Object> result = new ArrayList<>(2);
        result.add(decryptedMessageReceivedOK);
        result.add(hmacHash);
        return result;
    }

    public void OkHandShakeSend(boolean b, String hashAlgo, String messageDecryptS, byte[] hmacHash, byte[] decryptedMessageReceivedOK) throws Exception {
        if( messageDecryptS.equals( userName ) )
        {
            if( hashUser.equals("none")) {
                System.out.println("CLIENT_OK");
                if (b) {
                    byte[] encryptedMessageSend = SymmetricAlgorithm.encrypt(decryptedMessageReceivedOK, symmetricKey, encUser);
                    out.writeObject(encryptedMessageSend);
                } else if (encUser.equals("RSA")) {
                    byte[] encryptedMessageSend = RSA.encrypt(decryptedMessageReceivedOK, publicClientKey);
                    out.writeObject(encryptedMessageSend);
                }
            }
            else
            {
                if (encUser.equals("RSA")) {
                    byte[] hmacHashResult = HMac.hmacWithJava(hashAlgo, messageDecryptS, Base64.getEncoder().encodeToString(publicClientKey.getEncoded()));
                    if (Arrays.equals(hmacHashResult, hmacHash))
                    {
                        System.out.println("CLIENT_OK");
                    }
                    else
                    {
                        System.out.println("ERROR: TLS VALIDATION FAILED.");
                        throw new Exception("Received fatal alert: CLIENT_OK_FAILURE");
                    }

                    byte[] encryptedMessageSend = RSA.encrypt(decryptedMessageReceivedOK, publicClientKey);
                    ArrayList<Object> encryptedNamePlusHash = new ArrayList<>(2);
                    encryptedNamePlusHash.add( encryptedMessageSend );
                    encryptedNamePlusHash.add( HMac.hmacWithJava(hashAlgo, userName, Base64.getEncoder().encodeToString(publicKey.getEncoded())));
                    out.writeObject( encryptedNamePlusHash );
                }
                else if (b) {
                    byte[] hmacHashResult = HMac.hmacWithJava(hashAlgo, messageDecryptS, Base64.getEncoder().encodeToString(symmetricKey.getBytes()));
                    if (Arrays.equals(hmacHashResult, hmacHash))
                    {
                        System.out.println("CLIENT_OK");
                    }
                    else
                    {
                        System.out.println("ERROR: TLS VALIDATION FAILED.");
                        throw new Exception("Received fatal alert: CLIENT_OK_FAILURE");
                    }

                    byte[] encryptedMessageSend = SymmetricAlgorithm.encrypt(decryptedMessageReceivedOK, symmetricKey, encUser);
                    ArrayList<Object> encryptedNamePlusHash = new ArrayList<>(2);
                    encryptedNamePlusHash.add( encryptedMessageSend );
                    encryptedNamePlusHash.add( HMac.hmacWithJava(hashAlgo, userName, Base64.getEncoder().encodeToString(symmetricKey.getBytes())));
                    out.writeObject( encryptedNamePlusHash );
                }
            }
        }
        else
        {
            System.out.println("ERROR: TLS VALIDATION FAILED.");
            throw new Exception("Received fatal alert: CLIENT_OK_FAILURE");
        }
    }

    @Override
    public void run () {
        while ( server.isConnected( ) ) {
            try {
                byte[] message;
                byte[] hashReceived = new byte[0];
                if(hashUser.equals("none")) {
                    message = (byte[]) in.readObject();
                }
                else
                {
                    ArrayList<Object> encryptedNamePlusHash = (ArrayList<Object>) in.readObject( );
                    message = (byte[]) encryptedNamePlusHash.get(0);
                    hashReceived = (byte[]) encryptedNamePlusHash.get(1);
                }
                boolean b = encUser.equals("AES") || encUser.equals("DES") || encUser.equals("TripleDES");
                if(b)
                {
                    message = SymmetricAlgorithm.decrypt( message , this.symmetricKey, encUser );
                }
                else if( encUser.equals( "RSA" ) )
                {
                    message = RSA.decrypt( message , privateKey );
                }
                String messageDecrypted = new String( message , StandardCharsets.UTF_8 );
                if(!hashUser.equals("none")) {
                    byte[] hashResult = new byte[0];
                    if(b)
                    {
                        hashResult = HMac.hmacWithJava("Hmac" + hashUser, messageDecrypted, Base64.getEncoder().encodeToString(symmetricKey.getBytes()));
                    }
                    else if( encUser.equals( "RSA" ) )
                    {
                        hashResult = HMac.hmacWithJava("Hmac" + hashUser, messageDecrypted, Base64.getEncoder().encodeToString(publicKey.getEncoded()));
                    }

                    if (Arrays.equals(hashReceived, hashResult)) {
                        if( messageDecrypted.charAt(0) != '@' )
                            broadcastMessage( messageDecrypted.getBytes( StandardCharsets.UTF_8) , false );
                        else
                            specificMessage( messageDecrypted.getBytes( StandardCharsets.UTF_8 ) );
                    }
                    else
                    {
                        System.out.println("-- INVALID MESSAGE RECEIVED --");
                    }
                }
                else
                {
                    if( messageDecrypted.charAt(0) != '@' )
                        broadcastMessage( messageDecrypted.getBytes( StandardCharsets.UTF_8) , false );
                    else
                        specificMessage( messageDecrypted.getBytes( StandardCharsets.UTF_8 ) );
                }
            } catch ( IOException | ClassNotFoundException | NoSuchPaddingException | IllegalBlockSizeException |
                     NoSuchAlgorithmException | BadPaddingException | InvalidKeyException e ) {
                try {
                    removeClient( this );
                    break;
                } catch ( IOException ex ) {
                    ex.printStackTrace( );
                }
                e.printStackTrace( );
            }
        }
    }

    private void removeClient ( ClientHandler client ) throws IOException {
        clientHandlers.remove( client );
        server.close( );
        in.close( );
        out.close( );
    }

    public void broadcastMessage ( byte[] message, boolean isAnnouncement ) throws IOException {
        for ( ClientHandler client : clientHandlers ) {
            if ( ! this.equals( client ) ) {
                try {
                    ArrayList<Object> messageWithUserName = new ArrayList<>(2);
                    if ( !isAnnouncement ) {
                        messageWithUserName.add( this.userName );
                    } else {
                        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
                        messageWithUserName.add( "[" + timestamp + "]" );
                    }
                    byte[] messageEncrypted = serverEncryptionChoice(message, client);
                    messageWithUserName.add(messageEncrypted);

                    addUserNameToMessage( messageWithUserName , message , client );

                    /*if(! ( client.hashUser ).equals( "none" ) )
                    {
                        if ( ( client.encUser ).equals( "AES" ) || ( client.encUser ).equals( "DES" ) || ( client.encUser ).equals( "TripleDES" ) )
                        {
                            messageWithUserName.add( HMac.hmacWithJava( "Hmac" + client.hashUser , new String( message ) , Base64.getEncoder().encodeToString( client.symmetricKey.getBytes( ) ) ) );
                        }
                        else if( ( client.encUser ).equals( "RSA" ) )
                        {
                            messageWithUserName.add( HMac.hmacWithJava("Hmac" + client.hashUser , new String( message ), Base64.getEncoder().encodeToString( client.publicClientKey.getEncoded( ) ) ) );
                        }
                    }*/

                    client.out.writeObject( messageWithUserName );
                    client.out.flush( );
                } catch (IOException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
                         BadPaddingException | InvalidKeyException e ) {
                    removeClient( client );
                }
            }
        }
    }

    public void specificMessage ( byte[] message ) throws IOException {
        for ( ClientHandler client : clientHandlers ) {
            if (!this.equals(client)) {
                try {
                    ArrayList<Object> messageWithUserName = new ArrayList<>(2);
                    messageWithUserName.add( this.userName );
                    byte[] messageEncrypted = serverEncryptionChoice(message, client);
                    messageWithUserName.add(messageEncrypted);

                    addUserNameToMessage( messageWithUserName , message , client );
                    checkAndSendToUsersSpecified( message , client , messageWithUserName );

                } catch (IOException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
                         BadPaddingException | InvalidKeyException e) {
                    removeClient(client);
                }
            }
        }
    }

    public void checkAndSendToUsersSpecified (byte[] message , ClientHandler Client , ArrayList messageWithUsername) throws IOException {
        String message_verify = new String( message );
        String[] separated_message = message_verify.split(" ", 2 );
        String[] users = separated_message[0].split(",@", countChar( separated_message[1], "@" ) );
        users[0] = users[0].substring(1 );

        if ( Arrays.asList( users ).contains( Client.userName ) ) {
            Client.out.writeObject( messageWithUsername );
            Client.out.flush();
        }
    }

    public ArrayList addUserNameToMessage ( ArrayList messageWithUsername , byte[] message , ClientHandler client ) throws NoSuchAlgorithmException, InvalidKeyException {
        if(! ( client.hashUser ).equals( "none" ) )
        {
            if ( ( client.encUser ).equals( "AES" ) || ( client.encUser ).equals( "DES" ) || ( client.encUser ).equals( "TripleDES" ) )
            {
                messageWithUsername.add( HMac.hmacWithJava( "Hmac" + client.hashUser , new String( message ) , Base64.getEncoder().encodeToString( client.symmetricKey.getBytes( ) ) ) );
            }
            else if( ( client.encUser ).equals( "RSA" ) )
            {
                messageWithUsername.add( HMac.hmacWithJava("Hmac" + client.hashUser , new String( message ), Base64.getEncoder().encodeToString( client.publicClientKey.getEncoded( ) ) ) );
            }
        }
        return messageWithUsername;
    }


    private byte[] serverEncryptionChoice(byte[] message, ClientHandler client) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException {
        byte[] messageEncrypted = new byte[0];
        if ( ( client.encUser ).equals( "AES" ) || ( client.encUser ).equals( "DES" ) || ( client.encUser ).equals( "TripleDES" ) )
        {
            messageEncrypted = SymmetricAlgorithm.encrypt( message , client.symmetricKey, client.encUser );
        }
        else if( ( client.encUser ).equals( "RSA" ) )
        {
            messageEncrypted = RSA.encrypt( message , client.publicClientKey );
        }
        return messageEncrypted;
    }

    //FONTE: https://stackoverflow.com/questions/767759/occurrences-of-substring-in-a-string
    public static int countChar( String str, String target ) {
        return ( str.length() - str.replace( target, "" ).length( ) ) / target.length( );
    }
}
