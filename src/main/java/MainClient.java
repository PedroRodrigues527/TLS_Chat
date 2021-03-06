import java.util.Arrays;
import java.util.Objects;
import java.util.Scanner;

/**
 * Class responsible for getting user preferences,
 * and instance client with those preferences.
 */
public class MainClient {

    /**
     * Main method, to retrieve user choices:
     *      Username, Encryption algorithm, key size, hash algorithm.
     * And initializes the Client.
     *
     * @param args Array of Strings that stores the specified argument
     */
    public static void main ( String[] args ) throws Exception {
        String userName, encryptionUser, hashUser, keyExchangeUser;
        int keyUserSize;
        Scanner usrInput = new Scanner( System.in );

        //Insert username
        userName = usernameChoice(usrInput);

        //Insert encryption choice
        encryptionUser = encryptionChoice(usrInput);

        //Insert key size
        keyUserSize = keySizeChoice(encryptionUser, usrInput);

        //Insert hash mode
        hashUser = hashChoice(usrInput);

        //Insert key exchange mode
        if(encryptionUser.equals("RSA"))
        {
            System.out.println("Not possible to choose key exchange modes since they are only used in symmetric encryption (RSA is not). Finalizing...");
            keyExchangeUser = "none";
        }
        else {
            keyExchangeUser = keyExchangeChoice(usrInput);
        }

        System.out.println("Connecting to server...");

        Client client = new Client( "127.0.0.1" , 8000 , userName, encryptionUser, keyUserSize, hashUser, keyExchangeUser );
        client.readMessages( );
        client.sendMessages( usrInput );
    }

    /**
     * Method that will Retrieve the username written by the user
     *
     * @param usrInput Scanner that allows input from the user-side
     * @return username chosen
     */
    public static String usernameChoice(Scanner usrInput)
    {
        //Insert username
        String userchoice;
        do {
            System.out.println( "Write your username: ");
            userchoice = usrInput.nextLine( );
            if ( Objects.equals( userchoice , "" ) || userchoice.length( ) == 0 )
            {
                System.out.println( "ERROR: Unknown choice. Back to Username..." );
            }
        } while ( Objects.equals( userchoice , "" ) || userchoice.length( ) == 0 );
        return userchoice;
    }

    /**
     * Method that will Retrieve the encryption choice written by the user
     *
     * @param usrInput Scanner that allows input from the user-side
     * @return Encryption algorithm chosen
     */
    public static String encryptionChoice(Scanner usrInput)
    {
        //Insert encryption choice
        String userchoice;
        String[] encryptions = { "AES" , "DES" , "TripleDES" , "RSA" };
        do {
            System.out.println( "Choose type of encryption (AES, DES, TripleDES or RSA): ");
            userchoice = usrInput.nextLine( );
            if ( !Arrays.asList( encryptions ).contains( userchoice ) )
            {
                System.out.println( "ERROR: Unknown choice. Back to Choose Encryption..." );
            }
        } while (!Arrays.asList( encryptions ).contains( userchoice ) );
        return userchoice;
    }

    /**
     * Method that allows the user to Select the size of the key, taking into account the algorithm chosen.
     *
     * @param encryption_choice encryption algorithm chosen
     * @param usrInput Scanner that allows input from the user-side
     * @return size of the key selected
     */
    public static int keySizeChoice( String encryption_choice, Scanner usrInput )
    {
        //Insert key size choice
        String userchoice;
        int key_size_choice = 0;
        do {
            switch ( encryption_choice )
            {
                case "AES":
                    System.out.println( "Choose key size (128, 192 or 256 bits): ");
                    userchoice = usrInput.nextLine( );
                    String[] keySizes = { "128" , "192" , "256" };
                    if( !Arrays.asList( keySizes ).contains( userchoice ) )
                    {
                        System.out.println( "ERROR: Unknown choice. Back to Choose Key Size..." );
                    }
                    else
                    {
                        key_size_choice = Integer.parseInt( userchoice );
                    }
                    break;
                case "DES":
                    System.out.println( "Key size = 56 bits" );
                    key_size_choice = 56;
                    break;
                case "TripleDES":
                    System.out.println( "Key size = 168 bits" );
                    key_size_choice = 168;
                    break;
                case "RSA":
                    System.out.println( "Choose key size (1024, 2048 or 4096 bits): ");
                    userchoice = usrInput.nextLine( );
                    String[] keySizes_rsa = { "1024" , "2048" , "4096" };
                    if( !Arrays.asList( keySizes_rsa ).contains( userchoice ) )
                    {
                        System.out.println( "ERROR: Unknown choice. Back to Choose Key Size..." );
                    }
                    else
                    {
                        key_size_choice = Integer.parseInt( userchoice );
                    }
                    break;
                default:
                    break;
            }
        } while ( key_size_choice == 0 );
        return key_size_choice;
    }

    /**
     * Method that Allows the user to chose the hashs algorithm.
     *
     * @param usrInput Scanner that allows input from the user-side
     * @return hash chosen.
     */
    public static String hashChoice( Scanner usrInput)
    {
        //Insert choice
        String userchoice;
        String[] hashes = { "SHA1" , "SHA224" , "SHA256" , "SHA384" , "SHA512" , "MD5" };

        System.out.println( "Choose type of hash (none[default], SHA1, SHA224, SHA256, SHA384, SHA512 or MD5): " );
        userchoice = usrInput.nextLine( );
        if (!Arrays.asList( hashes ).contains( userchoice ) ) {
            userchoice = "none";
        }

        return userchoice;
    }

    /**
     * Method that Allows the user to chose the key exchange algorithm.
     *
     * @param usrInput Scanner that allows input from the user-side
     * @return key exchange selected
     */
    public static String keyExchangeChoice(Scanner usrInput)
    {
        //Insert choice
        String userchoice;
        String[] hashes = { "DH" , "ECDH" };

        System.out.println( "Choose type of key exchange (none[default], DH or ECDH): " );
        userchoice = usrInput.nextLine( );
        if (!Arrays.asList( hashes ).contains( userchoice ) ) {
            userchoice = "none";
        }

        return userchoice;
    }
}
