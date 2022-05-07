import java.io.IOException;

public class MainServer {
    /**
     * Main server method, initialize server
     * @param args
     * @throws IOException
     */
    public static void main ( String[] args ) throws IOException {
        Server server = new Server( 8000 );
        Thread serverThread = new Thread( server );
        serverThread.start( );
    }
}