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
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;

public class ClientHandler implements Runnable {

    public static final ArrayList<ClientHandler> clientHandlers = new ArrayList<>( );
    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private final String userName;
    private final Socket server;

    private final String encUser;
    private final int sizeKeyUser;
    private final String hashUser;

    private String symmetricKey;

    public ClientHandler ( Socket server ) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        this.server = server;
        this.in = new ObjectInputStream( server.getInputStream( ) );
        this.out = new ObjectOutputStream( server.getOutputStream( ) );

        //HELLO handshake
        ArrayList<Object> clientHello = (ArrayList<Object>) in.readObject( );
        this.userName = (String) clientHello.get( 0 );
        this.encUser = (String) clientHello.get( 1 );
        this.sizeKeyUser = (int) clientHello.get( 2 );
        this.hashUser = (String) clientHello.get( 3 );
        System.out.println("CLIENT_HELLO");

        if(encUser.equals("AES"))
        {
            AES aes = new AES();
            this.symmetricKey = aes.generateKey(sizeKeyUser);
            out.writeObject( symmetricKey );
        }

        //OK handshake
        byte[] encryptedMessageReceivedOK = (byte[]) in.readObject();
        byte[] decryptedMessageReceivedOK = new byte[0];
        if(encUser.equals("AES")) {
            decryptedMessageReceivedOK = AES.decrypt(encryptedMessageReceivedOK, symmetricKey);
        }

        String messageDecryptS = new String(decryptedMessageReceivedOK, StandardCharsets.UTF_8);
        if(messageDecryptS.equals(userName))
        {
            System.out.println("CLIENT_OK");
            if(encUser.equals("AES")) {
                byte[] encryptedMessageSend = AES.encrypt(decryptedMessageReceivedOK, symmetricKey);
                out.writeObject(encryptedMessageSend);
            }
        }

        //Announcement message
        clientHandlers.add( this );
        String announcement = (String) in.readObject( );
        broadcastMessage( announcement.getBytes( StandardCharsets.UTF_8 ), true);
    }

    @Override
    public void run () {
        while ( server.isConnected( ) ) {
            try {
                byte[] message = (byte[]) in.readObject( );
                if(encUser.equals("AES"))
                {
                    message = AES.decrypt(message, this.symmetricKey);
                }
                String messageDecrypted = new String(message, StandardCharsets.UTF_8);
                if(messageDecrypted.charAt(0) != '@')
                    broadcastMessage(messageDecrypted.getBytes(StandardCharsets.UTF_8), false);
                else
                    specificMessage(messageDecrypted.getBytes(StandardCharsets.UTF_8));
            } catch (IOException | ClassNotFoundException | NoSuchPaddingException | IllegalBlockSizeException |
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

    public void broadcastMessage ( byte[] message, boolean isAnnouncement) throws IOException {
        for ( ClientHandler client : clientHandlers ) {
            if ( ! this.equals( client ) ) {
                try {
                    ArrayList<Object> messageWithUserName = new ArrayList<>(2);
                    if (!isAnnouncement) {
                        messageWithUserName.add(this.userName);
                    } else {
                        Timestamp timestamp = new Timestamp(System.currentTimeMillis());
                        messageWithUserName.add("[" + timestamp + "]");
                    }
                    byte[] messageEncrypted = new byte[0];
                    if ((client.encUser).equals("AES"))
                    {
                        messageEncrypted = AES.encrypt(message, client.symmetricKey);
                    }
                    messageWithUserName.add(messageEncrypted);

                    client.out.writeObject(messageWithUserName);
                    client.out.flush();
                } catch (IOException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
                         BadPaddingException | InvalidKeyException e) {
                    removeClient(client);
                }
            }
        }
    }

    public void specificMessage ( byte[] message ) throws IOException {
        for ( ClientHandler client : clientHandlers ) {
            if (!this.equals(client)) {
                try {
                    ArrayList<Object> messageWithUserName = new ArrayList<>(2);
                    messageWithUserName.add(this.userName);
                    byte[] messageEncrypted = new byte[0];
                    if ((client.encUser).equals("AES"))
                    {
                        messageEncrypted = AES.encrypt(message, client.symmetricKey);
                    }
                    messageWithUserName.add(messageEncrypted);

                    String message_verify = new String( message );
                    String[] separated_message = message_verify.split(" ", 2);
                    String[] users = separated_message[0].split(",@", countChar(separated_message[1], "@"));
                    users[0] = users[0].substring(1);

                    if ( Arrays.asList(users).contains(client.userName) ) {
                        client.out.writeObject(messageWithUserName);
                        client.out.flush();
                    }
                } catch (IOException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException |
                         BadPaddingException | InvalidKeyException e) {
                    removeClient(client);
                }
            }
        }
    }

    //FONTE: https://stackoverflow.com/questions/767759/occurrences-of-substring-in-a-string
    public static int countChar(String str, String target) {
        return (str.length() - str.replace(target, "").length()) / target.length();
    }
}