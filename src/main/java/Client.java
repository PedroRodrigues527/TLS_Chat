import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Scanner;

public class Client {

    private final Socket client;
    private final ObjectInputStream in;
    private final ObjectOutputStream out;
    private final String userName;

    public Client ( String host , int port , String userName ) throws IOException {
        client = new Socket( host , port );
        this.userName = userName;
        out = new ObjectOutputStream( client.getOutputStream( ) );
        in = new ObjectInputStream( client.getInputStream( ) );
        out.writeObject( userName );
    }

    public void sendMessages () throws IOException {
        while ( client.isConnected( ) ) {
            Scanner usrInput = new Scanner( System.in );
            String message = usrInput.nextLine( );
            try {
                out.writeObject( message );
            } catch ( IOException e ) {
                closeConnection( );
                break;
            }
        }

    }

    public void readMessages () {
        new Thread( () -> {
            while ( client.isConnected( ) ) {
                try {
                    ArrayList<Object> messageWithUserName = (ArrayList<Object>) in.readObject( );
                    String userName = (String) messageWithUserName.get( 0 );
                    String messageDecrypted = new String( (byte[]) messageWithUserName.get( 1 ) );
                    System.out.println( userName + ": " + messageDecrypted );
                } catch ( IOException | ClassNotFoundException e ) {
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

    private void closeConnection () throws IOException {
        client.close( );
        out.close( );
        in.close( );
    }

}
