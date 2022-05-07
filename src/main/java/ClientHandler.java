import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
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

    /**
     * Constructor that receives user information from socket and does
     * handshake protocol ( similar to TLS )
     * @param server server socket
     * @throws Exception
     */
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

        boolean isSymmetricAlgorithm = encUser.equals("AES") || encUser.equals("DES") || encUser.equals("TripleDES");
        helloHandShakeSend( isSymmetricAlgorithm );


        //OK handshake
        String hashAlgo = "Hmac" + hashUser;
        ArrayList<Object> messagePlusHash = OkHandShakeReceived( isSymmetricAlgorithm );
        byte[] decryptedMessageReceivedOK = (byte[]) messagePlusHash.get( 0 );
        byte[] hmacHash = (byte[]) messagePlusHash.get( 1 );

        String messageDecryptS = new String(decryptedMessageReceivedOK, StandardCharsets.UTF_8 );
        OkHandShakeSend( isSymmetricAlgorithm , hashAlgo , messageDecryptS , hmacHash , decryptedMessageReceivedOK );

        //Announcement message
        clientHandlers.add( this );
        String announcement = (String) in.readObject( );
        broadcastMessage( announcement.getBytes( ), true );
    }

    /**
     * Parte of 'TLS' agreement between client and server.
     *
     * @param isSymmetric boolean that checks with algorithm is compatible with symmetric algorithms
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws ClassNotFoundException
     * @throws InvalidKeyException
     */
    public void helloHandShakeSend ( boolean isSymmetric ) throws IOException, NoSuchAlgorithmException, ClassNotFoundException, InvalidKeyException {
        if( isSymmetric )
        {
            if(keyExchangeUser.equals("none")) {
                SymmetricAlgorithm sa = new SymmetricAlgorithm();
                this.symmetricKey = sa.generateKey(sizeKeyUser, encUser);
                out.writeObject(symmetricKey);
            }
            else if(keyExchangeUser.equals("DH")) {
                //generate values
                int N, G;
                do {
                    N = DHNumberGenerator.generateP();
                    G = DHNumberGenerator.generateG(N);
                } while(!DHNumberGenerator.isPrime(N) || G <= 3);

                BigInteger privateKeyDH = BigInteger.valueOf(G-1);
                BigInteger publicKeyDH = DiffieHellman.generatePublicKey(BigInteger.valueOf(G), BigInteger.valueOf(N), privateKeyDH);

                ArrayList<Object> DHvalues = new ArrayList<>(3);
                DHvalues.add(N);
                DHvalues.add(G);
                DHvalues.add(publicKeyDH);
                out.writeObject(DHvalues);
                BigInteger publicClientKeyDH = (BigInteger) in.readObject( );

                BigInteger secretKeyDH = DiffieHellman.generateSecretKey(BigInteger.valueOf(N), publicClientKeyDH, privateKeyDH);
                byte[] secretKeyDHByte;
                if( encUser.equals( "AES" ) ) {
                    secretKeyDHByte = ByteBuffer.allocate((sizeKeyUser / Byte.SIZE)).put(secretKeyDH.toByteArray()).array();
                }
                else if ( encUser.equals( "TripleDES" ) )
                {
                    secretKeyDHByte = ByteBuffer.allocate(8*3).put(secretKeyDH.toByteArray()).array();
                }
                else {
                    secretKeyDHByte = ByteBuffer.allocate(8).put(secretKeyDH.toByteArray()).array();
                }
                SecretKeySpec secretKey = new SecretKeySpec( secretKeyDHByte , encUser );
                //https://stackoverflow.com/questions/26828649/diffiehellman-key-exchange-to-aes-or-desede-in-java
                this.symmetricKey = Base64.getEncoder().encodeToString(secretKey.getEncoded( ) );
            }
            else if(keyExchangeUser.equals("ECDH"))
            {
                ECDiffieHellman ecdh = new ECDiffieHellman();
                KeyPair keyPair = ecdh.generateKeyPair();
                PublicKey publicKeyECDH = ecdh.getPublicKey(keyPair);
                PrivateKey privateKeyECDH = ecdh.getPrivateKey(keyPair);

                out.writeObject(publicKeyECDH);
                PublicKey publicClientKeyECDH = (PublicKey) in.readObject();

                //https://stackoverflow.com/questions/26828649/diffiehellman-key-exchange-to-aes-or-desede-in-java
                byte[] secretKeyECDH = ecdh.getSecretKey(privateKeyECDH, publicClientKeyECDH);
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                byte[] bkey;
                if( encUser.equals( "AES" ) ) {
                    bkey = Arrays.copyOf(
                            sha256.digest(secretKeyECDH), sizeKeyUser / Byte.SIZE);
                }
                else if ( encUser.equals( "TripleDES" ) )
                {
                    bkey = Arrays.copyOf(
                            sha256.digest(secretKeyECDH), 8*3);
                }
                else {
                    bkey = Arrays.copyOf(
                            sha256.digest(secretKeyECDH), 8);
                }
                SecretKey desSpec = new SecretKeySpec(bkey, encUser);

                this.symmetricKey = Base64.getEncoder().encodeToString(desSpec.getEncoded());
            }
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

    /**
     * @param isSymmetric boolean that checks with algorithm is compatible with symmetric algorithms
     * @return
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws ClassNotFoundException
     */
    public ArrayList<Object> OkHandShakeReceived(boolean isSymmetric) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException, ClassNotFoundException {
        byte[] decryptedMessageReceivedOK = new byte[0];
        byte[] hmacHash = new byte[0];
        if( isSymmetric ) {
            if( hashUser.equals( "none" ) ) {
                byte[] encryptedMessageReceivedOK = (byte[]) in.readObject( );
                decryptedMessageReceivedOK = SymmetricAlgorithm.decrypt( encryptedMessageReceivedOK , symmetricKey , encUser );
            }
            else
            {
                ArrayList<Object> encryptedMessagePlusHash = (ArrayList<Object>) in.readObject( );
                byte[] encryptedMessageReceivedOK = (byte[]) encryptedMessagePlusHash.get( 0 );
                hmacHash = (byte[]) encryptedMessagePlusHash.get( 1 );
                decryptedMessageReceivedOK = SymmetricAlgorithm.decrypt( encryptedMessageReceivedOK , symmetricKey , encUser );
            }
        }
        else if( encUser.equals( "RSA" ) )
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

    /**
     * @param isSymmetric
     * @param hashAlgo
     * @param messageDecryptS
     * @param hmacHash
     * @param decryptedMessageReceivedOK
     * @throws Exception
     */
    public void OkHandShakeSend(boolean isSymmetric , String hashAlgo , String messageDecryptS , byte[] hmacHash , byte[] decryptedMessageReceivedOK ) throws Exception {
        if( messageDecryptS.equals( userName ) )
        {
            if( hashUser.equals( "none" ) ) {
                System.out.println( "CLIENT_OK" );
                if ( isSymmetric ) {
                    byte[] encryptedMessageSend = SymmetricAlgorithm.encrypt( decryptedMessageReceivedOK , symmetricKey , encUser );
                    out.writeObject(encryptedMessageSend);
                } else if ( encUser.equals( "RSA" ) ) {
                    byte[] encryptedMessageSend = RSA.encrypt( decryptedMessageReceivedOK , publicClientKey );
                    out.writeObject( encryptedMessageSend );
                }
            }
            else
            {
                if ( encUser.equals( "RSA" ) ) {
                    byte[] hmacHashResult = HMac.hmacWithJava( hashAlgo, messageDecryptS, Base64.getEncoder().encodeToString( publicClientKey.getEncoded( ) ) );
                    if ( Arrays.equals( hmacHashResult , hmacHash ) )
                    {
                        System.out.println( "CLIENT_OK" );
                    }
                    else
                    {
                        System.out.println( "ERROR: TLS VALIDATION FAILED." );
                        throw new Exception( "Received fatal alert: CLIENT_OK_FAILURE" );
                    }

                    byte[] encryptedMessageSend = RSA.encrypt( decryptedMessageReceivedOK , publicClientKey );
                    ArrayList<Object> encryptedNamePlusHash = new ArrayList<>(2);
                    encryptedNamePlusHash.add( encryptedMessageSend );
                    encryptedNamePlusHash.add( HMac.hmacWithJava(hashAlgo , userName , Base64.getEncoder().encodeToString( publicKey.getEncoded( ) ) ) );
                    out.writeObject( encryptedNamePlusHash );
                }
                else if ( isSymmetric ) {
                    byte[] hmacHashResult = HMac.hmacWithJava( hashAlgo, messageDecryptS, Base64.getEncoder().encodeToString( symmetricKey.getBytes( ) ) );
                    if ( Arrays.equals( hmacHashResult , hmacHash ) )
                    {
                        System.out.println( "CLIENT_OK" );
                    }
                    else
                    {
                        System.out.println( "ERROR: TLS VALIDATION FAILED." );
                        throw new Exception( "Received fatal alert: CLIENT_OK_FAILURE" );
                    }

                    byte[] encryptedMessageSend = SymmetricAlgorithm.encrypt( decryptedMessageReceivedOK , symmetricKey , encUser );
                    ArrayList<Object> encryptedNamePlusHash = new ArrayList<>(2);
                    encryptedNamePlusHash.add( encryptedMessageSend );
                    encryptedNamePlusHash.add( HMac.hmacWithJava(hashAlgo, userName, Base64.getEncoder().encodeToString(symmetricKey.getBytes())));
                    out.writeObject( encryptedNamePlusHash );
                }
            }
        }
        else
        {
            System.out.println( "ERROR: TLS VALIDATION FAILED." );
            throw new Exception( "Received fatal alert: CLIENT_OK_FAILURE" );
        }
    }

    /**
     *
     */
    @Override
    public void run () {
        while ( server.isConnected( ) ) {
            try {
                byte[] message;
                byte[] hashReceived = new byte[0];
                if( hashUser.equals( "none" ) ) {
                    message = (byte[]) in.readObject( );
                }
                else
                {
                    ArrayList<Object> encryptedNamePlusHash = (ArrayList<Object>) in.readObject( );
                    message = (byte[]) encryptedNamePlusHash.get( 0 );
                    hashReceived = (byte[]) encryptedNamePlusHash.get( 1 );
                }
                boolean isSymmetricAlgorithm = encUser.equals( "AES" ) || encUser.equals( "DES" ) || encUser.equals( "TripleDES" );
                if( isSymmetricAlgorithm )
                {
                    message = SymmetricAlgorithm.decrypt( message , this.symmetricKey , encUser );
                }
                else if( encUser.equals( "RSA" ) )
                {
                    message = RSA.decrypt( message , privateKey );
                }
                String messageDecrypted = new String( message , StandardCharsets.UTF_8 );
                if( ! hashUser.equals( "none" ) ) {
                    byte[] hashResult = new byte[0];
                    if( isSymmetricAlgorithm )
                    {
                        hashResult = HMac.hmacWithJava("Hmac" + hashUser , messageDecrypted , Base64.getEncoder().encodeToString( symmetricKey.getBytes( ) ) );
                    }
                    else if( encUser.equals( "RSA" ) )
                    {
                        hashResult = HMac.hmacWithJava("Hmac" + hashUser , messageDecrypted , Base64.getEncoder().encodeToString( publicKey.getEncoded( ) ) );
                    }

                    if ( Arrays.equals( hashReceived , hashResult ) ) {
                        if( messageDecrypted.charAt(0) != '@' )
                            broadcastMessage( messageDecrypted.getBytes( StandardCharsets.UTF_8) , false );
                        else
                            specificMessage( messageDecrypted.getBytes( StandardCharsets.UTF_8 ) );
                    }
                    else
                    {
                        System.out.println( "-- INVALID MESSAGE RECEIVED --" );
                    }
                }
                else
                {
                    if( messageDecrypted.charAt(0) != '@' )
                        broadcastMessage( messageDecrypted.getBytes( StandardCharsets.UTF_8 ) , false );
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

    /**
     * Remove client
     * @param client client online
     * @throws IOException
     */
    private void removeClient ( ClientHandler client ) throws IOException {
        clientHandlers.remove( client );
        server.close( );
        in.close( );
        out.close( );
    }

    /**
     * Broadcast a message to every user online
     * @param message array of byte message received
     * @param isAnnouncement boolean to verify if is announcement
     * @throws IOException
     */
    public void broadcastMessage ( byte[] message, boolean isAnnouncement ) throws IOException {
        for ( ClientHandler client : clientHandlers ) {
            if ( ! this.equals( client ) ) {
                try {
                    ArrayList<Object> messageWithUserName = new ArrayList<>(2);
                    if ( !isAnnouncement ) {
                        messageWithUserName.add( this.userName );
                    } else {
                        Timestamp timestamp = new Timestamp( System.currentTimeMillis( ) );
                        messageWithUserName.add( "[" + timestamp + "]" );
                    }
                    byte[] messageEncrypted = serverEncryptionChoice(message, client);
                    messageWithUserName.add(messageEncrypted);

                    byte[] hashCreated = generateHash( message , client );
                    messageWithUserName.add(hashCreated);

                    client.out.writeObject( messageWithUserName );
                    client.out.flush( );
                } catch (IOException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
                         BadPaddingException | InvalidKeyException e ) {
                    removeClient( client );
                }
            }
        }
    }

    /**
     * Sends a specific message to a user, by using @NAME_OF_THE_USER, where NAME_OF_THE_USER represents username of the user to send the message
     * @param message array of byte message received
     * @throws IOException
     */
    public void specificMessage ( byte[] message ) throws IOException {
        for ( ClientHandler client : clientHandlers ) {
            if (!this.equals(client)) {
                try {
                    ArrayList<Object> messageWithUserName = new ArrayList<>(2);
                    messageWithUserName.add( this.userName );
                    byte[] messageEncrypted = serverEncryptionChoice(message, client);
                    messageWithUserName.add(messageEncrypted);

                    byte[] hashCreated = generateHash( message , client );
                    messageWithUserName.add(hashCreated);

                    checkAndSendToUsersSpecified( message , client , messageWithUserName );

                } catch (IOException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
                         BadPaddingException | InvalidKeyException e) {
                    removeClient(client);
                }
            }
        }
    }

    /**
     * Verifies the user to send the message
     * @param message array of byte message received
     * @param Client Clients connected
     * @param messageWithUsername Arraylist that contains message and username
     * @throws IOException
     */
    public void checkAndSendToUsersSpecified (byte[] message , ClientHandler Client , ArrayList<Object> messageWithUsername) throws IOException {
        String message_verify = new String( message );
        String[] separated_message = message_verify.split(" ", 2 );
        String[] users = separated_message[0].split(",@", countChar( separated_message[1], "@" ) );
        users[0] = users[0].substring(1 );

        if ( Arrays.asList( users ).contains( Client.userName ) ) {
            Client.out.writeObject( messageWithUsername );
            Client.out.flush();
        }
    }

    /**
     * Generates tha respective hash, having into account the algorithm currently using
     * @param message array of byte message received
     * @param client Client online
     * @return hash created
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public byte[] generateHash (byte[] message , ClientHandler client ) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] hashCreated = new byte[0];
        if(! ( client.hashUser ).equals( "none" ) )
        {
            if ( ( client.encUser ).equals( "AES" ) || ( client.encUser ).equals( "DES" ) || ( client.encUser ).equals( "TripleDES" ) )
            {
                hashCreated = HMac.hmacWithJava( "Hmac" + client.hashUser , new String( message ) , Base64.getEncoder().encodeToString( client.symmetricKey.getBytes( ) ) );
            }
            else if( ( client.encUser ).equals( "RSA" ) )
            {
                hashCreated = HMac.hmacWithJava("Hmac" + client.hashUser , new String( message ), Base64.getEncoder().encodeToString( client.publicClientKey.getEncoded( ) ) );
            }
        }
        return hashCreated;
    }


    /**
     * Encrypts message with respectively algorithm
     * @param message array of byte message received
     * @param client client online
     * @return message encrypted
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws IOException
     */
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

    /**
     * @param str
     * @param target
     * @return
     */
    //FONTE: https://stackoverflow.com/questions/767759/occurrences-of-substring-in-a-string
    public static int countChar( String str, String target ) {
        return ( str.length() - str.replace( target, "" ).length( ) ) / target.length( );
    }
}
