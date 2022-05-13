import java.io.IOException;

/**
 * Class responsible for initialize the Server
 */
public class MainServer {
    /**
     * Main server method, initialize server
     * @param args Array of Strings that stores the specified argument
     * @throws IOException
     */
    public static void main ( String[] args ) throws IOException {
        Server server = new Server( 8000 );
        Thread serverThread = new Thread( server );
        serverThread.start( );
    }
}