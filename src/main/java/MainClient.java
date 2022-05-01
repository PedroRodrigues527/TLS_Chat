import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;
import java.util.Scanner;

public class MainClient {

    public static void main ( String[] args ) throws IOException {
        Scanner usrInput = new Scanner( System.in );

        //Insert username
        String userName = usernameChoice();

        //Insert encryption choice
        String encryptionUser = encryptionChoice();

        //Insert key size
        //String keyUserSize = keySizeChoice();

        Client client = new Client( "127.0.0.1" , 8000 , userName );
        client.readMessages( );
        client.sendMessages( );
    }

    public static String usernameChoice()
    {
        Scanner usrInput = new Scanner( System.in );

        //Insert username
        String userchoice;
        do {
            System.out.println( "Write your username: ");
            userchoice = usrInput.nextLine();
            if (Objects.equals(userchoice, "") || userchoice.length() == 0)
            {
                System.out.println( "ERROR: Unknown choice. Back to Username..." );
            }
        } while (Objects.equals(userchoice, "") || userchoice.length() == 0);
        return userchoice;
    }

    public static String encryptionChoice()
    {
        Scanner usrInput = new Scanner( System.in );

        //Insert encryption choice
        String userchoice;
        String[] encryptions = {"AES", "DES", "3DES", "RSA"};
        do {
            System.out.println( "Choose type of encryption (AES, DES, 3DES or RSA): ");
            userchoice = usrInput.nextLine();
            if ( !Arrays.asList(encryptions).contains(userchoice) )
            {
                System.out.println( "ERROR: Unknown choice. Back to Choose Encryption..." );
            }
        } while (!Arrays.asList(encryptions).contains(userchoice));
        return userchoice;
    }

    public static String keySizeChoice()
    {
        Scanner usrInput = new Scanner( System.in );

        //Insert key size choice
        String userchoice;
        String[] encryptions = {"AES", "DES", "3DES", "RSA"};
        do {
            System.out.println( "Choose type of encryption (AES, DES, 3DES or RSA): ");
            userchoice = usrInput.nextLine();
            if ( !Arrays.asList(encryptions).contains(userchoice) )
            {
                System.out.println( "ERROR: Unknown choice. Back to Choose Encryption..." );
            }
        } while (!Arrays.asList(encryptions).contains(userchoice));
        return userchoice;
    }
}