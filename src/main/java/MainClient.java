import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;
import java.util.Scanner;

public class MainClient {

    public static void main ( String[] args ) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String userName, encryptionUser, hashUser;
        int keyUserSize;
        if(args.length == 0) {
            //Insert username
            userName = usernameChoice();

            //Insert encryption choice
            encryptionUser = encryptionChoice();

            //Insert key size
            keyUserSize = keySizeChoice(encryptionUser);

            //Insert hash mode
            hashUser = hashChoice(encryptionUser);
        }
        else
        {
            userName = args[0];
            encryptionUser = args[1];
            keyUserSize = Integer.parseInt(args[2]);
            hashUser = args[3];
        }

        System.out.println("Connecting to server...");

        Client client = new Client( "127.0.0.1" , 8000 , userName, encryptionUser, keyUserSize, hashUser );
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
            userchoice = usrInput.nextLine( );
            if ( Objects.equals( userchoice , "" ) || userchoice.length( ) == 0 )
            {
                System.out.println( "ERROR: Unknown choice. Back to Username..." );
            }
        } while ( Objects.equals( userchoice , "" ) || userchoice.length( ) == 0 );
        return userchoice;
    }

    public static String encryptionChoice()
    {
        Scanner usrInput = new Scanner( System.in );

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

    public static int keySizeChoice( String encryption_choice )
    {
        Scanner usrInput = new Scanner( System.in );

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

    public static String hashChoice(String encryptionChoice)
    {
        Scanner usrInput = new Scanner( System.in );

        //Insert choice
        String userchoice;
        String[] hashes = { "SHA-256" , "SHA-512" , "MD4" , "MD5" };

        System.out.println( "Choose type of hash (none[default], SHA-256, SHA-512, MD4 or MD5): " );
        userchoice = usrInput.nextLine( );
        if (!Arrays.asList( hashes ).contains( userchoice ) ) {
            userchoice = "none";
        }

        return userchoice;
    }
}
