import java.io.IOException;

public class MainServer {

    public static void main ( String[] args ) throws IOException {
        Server server = new Server( 8000 );
        Thread serverThread = new Thread( server );
        serverThread.start( );
    }

}