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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class Client {
    //variáveis de instância
    private final Socket client;
    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private final String userName, encryptionUser, hashUser, keyExchangeUser;
    private final int keySizeUser;

    private String symmetricKey;

    private PublicKey publicKey;
    private PrivateKey privateKey;
    private PublicKey publicServerKey;

    /**
     * @param host ip address where server is online
     * @param port network port where server is online
     * @param userName username chosen by the user
     * @param encryptionUser encryption algorithm picked by user
     * @param keySizeUser size of the key selected by the user
     * @param hashUser hash algorithm selected by the user
     * @param keyExchangeUser key exchange chose by the user
     * @throws Exception
     */
    public Client ( String host , int port , String userName, String encryptionUser, int keySizeUser, String hashUser, String keyExchangeUser ) throws Exception {
        client = new Socket( host , port );
        this.userName = userName;
        this.encryptionUser = encryptionUser;
        this.keySizeUser = keySizeUser;
        this.hashUser = hashUser;
        this.keyExchangeUser = keyExchangeUser;

        out = new ObjectOutputStream( client.getOutputStream( ) );
        in = new ObjectInputStream( client.getInputStream( ) );

        //HELLO handshake
        helloHandShakeSend( );
        helloHandShakeReceived();

        //OK handshake
        okHandShakeSend( );
        okHandShakeReceived();

        //Announcement message
        out.writeObject( "O cliente '" + userName + "' ligou-se ao Chat." );
        System.out.println( "Agora já pode enviar mensagens no Chat." );
    }

    /**
     * Send to client handler user information and his choices
     * @throws IOException
     */
    public void helloHandShakeSend () throws IOException {
        ArrayList<Object> cipherSuite = new ArrayList<>(5);
        cipherSuite.add( userName );
        cipherSuite.add( encryptionUser );
        cipherSuite.add( keySizeUser );
        cipherSuite.add( hashUser );
        cipherSuite.add( keyExchangeUser );
        out.writeObject( cipherSuite );
    }

    /**
     *Method responsible for the return of the Server_Hello, utilizing all the encryption methods and protocols.
     *
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public void helloHandShakeReceived () throws IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeyException {
        if ( encryptionUser.equals( "AES" ) || encryptionUser.equals( "DES" ) || encryptionUser.equals( "TripleDES" ) ) {
            if(keyExchangeUser.equals("none")) {
                symmetricKey = (String) in.readObject( );
            }
            else if(keyExchangeUser.equals("DH")) {
                //get and generate values
                ArrayList<Object> DHvalues = (ArrayList<Object>) in.readObject();
                int N = (int) DHvalues.get(0);
                int G = (int) DHvalues.get(1);
                BigInteger publicServerKeyDH = (BigInteger) DHvalues.get(2);

                BigInteger privateKeyDH = BigInteger.valueOf(G-2);
                BigInteger publicKeyDH = DiffieHellman.generatePublicKey(BigInteger.valueOf(G), BigInteger.valueOf(N), privateKeyDH);
                out.writeObject(publicKeyDH);

                BigInteger secretKeyDH = DiffieHellman.generateSecretKey(BigInteger.valueOf(N), publicServerKeyDH, privateKeyDH);
                byte[] secretKeyDHByte;
                if( encryptionUser.equals( "AES" ) ) {
                    secretKeyDHByte = ByteBuffer.allocate((keySizeUser / Byte.SIZE)).put(secretKeyDH.toByteArray()).array();
                }
                else if ( encryptionUser.equals( "TripleDES" ) )
                {
                    secretKeyDHByte = ByteBuffer.allocate(8*3).put(secretKeyDH.toByteArray()).array();
                }
                else {
                    secretKeyDHByte = ByteBuffer.allocate(8).put(secretKeyDH.toByteArray()).array();
                }
                SecretKeySpec secretKey = new SecretKeySpec( secretKeyDHByte , encryptionUser );

                this.symmetricKey = Base64.getEncoder().encodeToString(secretKey.getEncoded( ) );
            }
            else if(keyExchangeUser.equals("ECDH"))
            {
                ECDiffieHellman ecdh = new ECDiffieHellman();
                KeyPair keyPair = ecdh.generateKeyPair();
                PublicKey publicKeyECDH = ecdh.getPublicKey(keyPair);
                PrivateKey privateKeyECDH = ecdh.getPrivateKey(keyPair);

                PublicKey publicServerKeyECDH = (PublicKey) in.readObject();
                out.writeObject(publicKeyECDH);

                byte[] secretKeyECDH = ecdh.getSecretKey(privateKeyECDH, publicServerKeyECDH);
                MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                byte[] bkey;
                if( encryptionUser.equals( "AES" ) ) {
                    bkey = Arrays.copyOf(
                            sha256.digest(secretKeyECDH), keySizeUser / Byte.SIZE);
                }
                else if ( encryptionUser.equals( "TripleDES" ) )
                {
                    bkey = Arrays.copyOf(
                            sha256.digest(secretKeyECDH), 8*3);
                }
                else {
                    bkey = Arrays.copyOf(
                            sha256.digest(secretKeyECDH), 8);
                }
                SecretKey desSpec = new SecretKeySpec(bkey, encryptionUser);

                this.symmetricKey = Base64.getEncoder().encodeToString(desSpec.getEncoded());
            }
        }
        else if ( encryptionUser.equals( "RSA" ) ) {
            publicServerKey = ( PublicKey ) in.readObject( );
        }
        System.out.println( "SERVER_HELLO" );
    }

    /**
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws IOException
     * @throws InvalidKeyException
     */
    public void okHandShakeSend ( ) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException {
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

    /**
     * Method responsible for the OK Message on the receiver end, in order to ensure the safety of the Message.
     *
     * @throws Exception
     */
    public void okHandShakeReceived ( ) throws Exception {
        if(hashUser.equals("none")) {
            byte[] encryptedMessageReceivedOK = (byte[]) in.readObject();
            byte[] decryptedMessageReceivedOK = new byte[0];
            decryptedMessageReceivedOK = decryptMessageOkReceive(decryptedMessageReceivedOK, encryptedMessageReceivedOK);

            String messageDecryptS = new String(decryptedMessageReceivedOK, StandardCharsets.UTF_8);
            if (messageDecryptS.equals(userName)) {
                System.out.println("SERVER_OK");
            }
            else
            {
                System.out.println("ERROR: TLS VALIDATION FAILED.");
                throw new Exception("Received fatal alert: SERVER_OK_FAILURE");
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
            else
            {
                System.out.println("ERROR: TLS VALIDATION FAILED.");
                throw new Exception("Received fatal alert: SERVER_OK_FAILURE");
            }
        }
    }

    /**
     * Method responsible with the return of the decrypted Message utilizing the Encryption protocols.
     *
     * @param decryptedMessage
     * @param encryptedMessage
     * @return
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws IOException
     * @throws InvalidKeyException
     */
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

    /**
     * Send messages as long as the client is connected and also uses encrpytion protocols in order to maintain the security of the message's context
     *
     * @throws IOException
     */
    public void sendMessages ( Scanner usrInput ) throws IOException {
        while ( client.isConnected( ) ) {

            String message;
            do {
                message = usrInput.nextLine( );
                if(message.equals(""))
                {
                    System.out.println("You can't send an empty message.");
                }
                else if(message.equals("Exit"))
                {
                    System.out.println("Exiting Chat...");
                    closeConnection();
                    return;
                }
            } while(message.equals(""));
            byte[] messageByte = new byte[0];
            try {
                boolean b = encryptionUser.equals("AES") || encryptionUser.equals("DES") || encryptionUser.equals("TripleDES");
                if( hashUser.equals("none")) {
                    if (encryptionUser.equals("RSA")) {
                        messageByte = RSA.encrypt(message.getBytes(StandardCharsets.UTF_8), publicServerKey);
                    } else if (b) {
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
                    } else if (b) {
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

    /**
     * Method responsible with Reading the respective messages
     */
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

                    boolean b = encryptionUser.equals("AES") || encryptionUser.equals("DES") || encryptionUser.equals("TripleDES");
                    if (b)
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
                        if (b)
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

    /**
     * Method that Closes the connection on the client side
     *
     * @throws IOException
     */
    private void closeConnection () throws IOException {
        client.close( );
        out.close( );
        in.close( );
    }

    /**
     * Gets userName
     *
     * @return value of userName
     */
    public String getUserName() {
        return userName;
    }

    /**
     * Gets encryptionUser
     *
     * @return value of encryptionUser
     */
    public String getEncryptionUser() {
        return encryptionUser;
    }

    /**
     * Gets hashUser
     *
     * @return value of hashUser
     */
    public String getHashUser() {
        return hashUser;
    }

    /**
     * Gets keyExchangeUser
     *
     * @return value of keyExchangeUser
     */
    public String getKeyExchangeUser() {
        return keyExchangeUser;
    }

    /**
     * Gets keySizeUser
     *
     * @return value of keySizeUser
     */
    public int getKeySizeUser() {
        return keySizeUser;
    }

}
