import org.junit.jupiter.api.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

import static org.junit.jupiter.api.Assertions.*;

class MainClientTest {

    public void detectInputOutput(String userInput)
    {
        ByteArrayInputStream bais = new ByteArrayInputStream(userInput.getBytes());
        System.setIn(bais);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream printStream = new PrintStream(baos);
        System.setOut(printStream);
    }
    @Nested
    @DisplayName("Client choices' tests")
    class ChoiceTests
    {
        @DisplayName ("Test username choice")
        @Test
        public void testUsernameChoice() {
            String userInput = String.format("User%s",
                    System.lineSeparator());
            detectInputOutput(userInput);

            String userNameOutput = MainClient.usernameChoice(); // call the username choice method


            String userInput2 = String.format("%stest%s",
                    System.lineSeparator(),
                    System.lineSeparator());
            detectInputOutput(userInput2);

            String userNameOutput2 = MainClient.usernameChoice();

            // checkout output
            assertAll(
                    () -> assertEquals("test",userNameOutput2),
                    () -> assertEquals("User",userNameOutput)
            );
        }

        @DisplayName ("Test encryption choice")
        @Test
        public void testEncryptionChoice() {
            String userInput = String.format("RSA%s",
                    System.lineSeparator());
            detectInputOutput(userInput);

            String encryptionOutput = MainClient.encryptionChoice(); // call the encryption choice method


            String userInput2 = String.format("%st%sAES%s",
                    System.lineSeparator(),
                    System.lineSeparator(),
                    System.lineSeparator());
            detectInputOutput(userInput2);

            String encryptionOutput2 = MainClient.encryptionChoice();

            // checkout output
            assertAll(
                    () -> assertEquals("AES",encryptionOutput2),
                    () -> assertEquals("RSA",encryptionOutput),
                    () -> assertNotEquals("AES",encryptionOutput)
            );
        }

        @DisplayName ("Test key size choice")
        @Test
        public void testKeySizeChoice() {
            String userInput = String.format("%s128%s",
                    System.lineSeparator(),
                    System.lineSeparator());
            detectInputOutput(userInput);

            int keySizeOutput = MainClient.keySizeChoice("AES"); // call the key size choice method


            String userInput2 = String.format("%s1%s1024%s",
                    System.lineSeparator(),
                    System.lineSeparator(),
                    System.lineSeparator());
            detectInputOutput(userInput2);

            int keySizeOutput2 = MainClient.keySizeChoice("RSA");

            int keySizeOutput3 = MainClient.keySizeChoice("DES");

            int keySizeOutput4 = MainClient.keySizeChoice("TripleDES");

            // checkout output
            assertAll(
                    () -> assertEquals(1024,keySizeOutput2),
                    () -> assertEquals(128,keySizeOutput),
                    () -> assertNotEquals(1,keySizeOutput2),
                    () -> assertEquals(56,keySizeOutput3),
                    () -> assertEquals(168,keySizeOutput4),
                    () -> assertNotEquals(112,keySizeOutput4)
            );
        }

        @DisplayName ("Test hash choice")
        @Test
        public void testHashChoice() {
            String userInput = String.format("%s",
                    System.lineSeparator());
            detectInputOutput(userInput);

            String hashOutput = MainClient.hashChoice(); // call the hash choice method


            String userInput2 = String.format("SHA256%s",
                    System.lineSeparator());
            detectInputOutput(userInput2);

            String hashOutput2 = MainClient.hashChoice();

            // checkout output
            assertAll(
                    () -> assertEquals("SHA256",hashOutput2),
                    () -> assertEquals("none",hashOutput),
                    () -> assertNotEquals("SHA512",hashOutput2)
            );
        }
    }

   /* @Nested
    @DisplayName("MainClient Test")
    class testMainClient
    {
        private Server server;
        private Thread serverThread;

        @BeforeEach
        void setUp() throws IOException {
            this.server = new Server(8000);
            serverThread = new Thread( server );
            serverThread.start();
            try{
                serverThread.join();
            }catch(Exception e){
                e.printStackTrace();
            }
            MainServer.main(new String[0]);
        }

        @DisplayName ("Test client choices")
        @Test
        public void testClientChoices() throws NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, ClassNotFoundException {

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PrintStream printStream = new PrintStream(baos);
            System.setOut(printStream);

            String[] userInput = {"user", "DES", "56", "none"};
            MainClient.main(userInput);

            assertEquals("t", baos.toString());
        }

    }*/
}