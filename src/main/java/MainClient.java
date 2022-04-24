import java.io.IOException;
import java.util.Scanner;

public class MainClient {

    public static void main ( String[] args ) throws IOException {
        Scanner usrInput = new Scanner( System.in );
        System.out.println( "Write your username" );
        String userName = usrInput.nextLine( );
        Client client = new Client( "127.0.0.1" , 8000 , userName );
        client.readMessages( );
        client.sendMessages( );

    }

}