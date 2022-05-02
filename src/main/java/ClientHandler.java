import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

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
        System.out.println("CLIENT_HELLO ");
        out.writeObject( userName );
        clientHandlers.add( this );

        String announcement = (String) in.readObject( );
        broadcastMessage( announcement.getBytes( StandardCharsets.UTF_8 ), true );
    }

    @Override
    public void run () {
        while ( server.isConnected( ) ) {
            try {
                String message = (String) in.readObject( );
                broadcastMessage( message.getBytes( StandardCharsets.UTF_8 ), false );
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

    public void broadcastMessage ( byte[] message, boolean isAnouncement ) throws IOException {
        for ( ClientHandler client : clientHandlers ) {
            if ( ! this.equals( client ) ) {
                try {
                    ArrayList<Object> messageWithUserName = new ArrayList<>( 2 );

                    if(!isAnouncement) {
                        messageWithUserName.add(this.userName);
                    }
                    else
                    {
                        messageWithUserName.add("");
                    }
                    messageWithUserName.add( message );
                    client.out.writeObject( messageWithUserName );
                    client.out.flush( );
                } catch ( IOException e ) {
                    removeClient( client );
                }
            }
        }
    }

}