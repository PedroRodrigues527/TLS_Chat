import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;

public class ClientHandler implements Runnable {

    public static final ArrayList<ClientHandler> clientHandlers = new ArrayList<>( );
    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private final String userName;
    private final Socket server;

    public ClientHandler ( Socket server ) throws IOException, ClassNotFoundException {
        this.server = server;
        this.in = new ObjectInputStream( server.getInputStream( ) );
        this.out = new ObjectOutputStream( server.getOutputStream( ) );
        this.userName = (String) in.readObject( );

        //HELLO handshake
        System.out.println("CLIENT_HELLO");
        out.writeObject( userName );

        //Announcement message
        clientHandlers.add( this );
        String announcement = (String) in.readObject( );
        broadcastMessage( announcement.getBytes( StandardCharsets.UTF_8 ), true, false );
    }

    @Override
    public void run () {
        while ( server.isConnected( ) ) {
            try {
                String message = (String) in.readObject( );
                broadcastMessage(message.getBytes(StandardCharsets.UTF_8), false, message.charAt(0) == '@');
            } catch ( IOException | ClassNotFoundException e ) {
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

    public void broadcastMessage ( byte[] message, boolean isAnnouncement, boolean isPrivate ) throws IOException {
        for ( ClientHandler client : clientHandlers ) {
            if ( ! this.equals( client ) ) {
                if ( !isPrivate ) {
                    try {
                        ArrayList<Object> messageWithUserName = new ArrayList<>(2);
                        if (!isAnnouncement) {
                            messageWithUserName.add(this.userName);
                        } else {
                            Timestamp timestamp = new Timestamp(System.currentTimeMillis());
                            messageWithUserName.add("[" + timestamp + "]");
                        }
                        messageWithUserName.add(message);
                        client.out.writeObject(messageWithUserName);
                        client.out.flush();
                    } catch (IOException e) {
                        removeClient(client);
                    }
                }
                else {
                    //mensagem especifica para users
                    try {
                        ArrayList<Object> messageWithUserName = new ArrayList<>(2);
                        messageWithUserName.add(this.userName);
                        messageWithUserName.add(message);

                        String message_verify = new String( (byte[]) messageWithUserName.get( 1 ) );
                        String[] separated_message = message_verify.split(" ", 2);
                        String[] users = separated_message[0].split(",@", countChar(separated_message[1], "@"));
                        users[0] = users[0].substring(1);

                        if ( Arrays.asList(users).contains(client.userName) ) {
                            client.out.writeObject(messageWithUserName);
                            client.out.flush();
                        }
                    } catch (IOException e) {
                        removeClient(client);
                    }
                }
            }
        }
    }

    //FONTE: https://stackoverflow.com/questions/767759/occurrences-of-substring-in-a-string
    public static int countChar(String str, String target) {
        return (str.length() - str.replace(target, "").length()) / target.length();
    }
}