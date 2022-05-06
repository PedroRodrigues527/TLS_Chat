import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Server implements Runnable {

    private final ServerSocket server;

    public Server ( int port ) throws IOException {
        server = new ServerSocket( port );
    }

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
                closeConnection( );
            } catch ( IOException ex ) {
                ex.printStackTrace( );
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void closeConnection () throws IOException {
        server.close( );
    }

}