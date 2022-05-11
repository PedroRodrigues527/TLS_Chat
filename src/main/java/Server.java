import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * Class responsible for the implementation on the Server-side
 */
public class Server implements Runnable {

    private final ServerSocket server;

    /**
     * Implementation of the Server Constructor
     *
     * @param port
     * @throws IOException
     */
    public Server ( int port ) throws IOException {
        server = new ServerSocket( port );
    }

    /**
     * Method responsible for the execution of the Server, utilizing Sockets in order to allow communication between the different processes.
     */
    @Override
    public void run () {
        try {
            while ( ! server.isClosed( ) ) {
                Socket client = server.accept( );
                ClientHandler clientHandler = new ClientHandler( client );
                Thread thread = new Thread( clientHandler );
                thread.start( );
            }
        } catch ( IOException | ClassNotFoundException e ) {
            try {
                server.close( );
            } catch ( IOException ex ) {
                ex.printStackTrace( );
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}