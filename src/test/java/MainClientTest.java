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
import java.util.concurrent.locks.ReentrantLock;

import static org.junit.jupiter.api.Assertions.*;

class MainClientTest {

    @Nested
    @DisplayName("Client choices' tests")
    class ChoiceTests
    {
        @DisplayName ("Test username choice")
        @Test
        public void testUsernameChoice() {
            String userInput = String.format("User%s",
                    System.lineSeparator());
            ByteArrayInputStream bais = new ByteArrayInputStream(userInput.getBytes());
            System.setIn(bais);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PrintStream printStream = new PrintStream(baos);
            System.setOut(printStream);

            String userNameOutput = MainClient.usernameChoice(); // call the username choice method


            String userInput2 = String.format("%stest%s",
                    System.lineSeparator(),
                    System.lineSeparator());
            ByteArrayInputStream bais2 = new ByteArrayInputStream(userInput2.getBytes());
            System.setIn(bais2);

            ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
            PrintStream printStream2 = new PrintStream(baos2);
            System.setOut(printStream2);

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
            ByteArrayInputStream bais = new ByteArrayInputStream(userInput.getBytes());
            System.setIn(bais);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PrintStream printStream = new PrintStream(baos);
            System.setOut(printStream);

            String encryptionOutput = MainClient.encryptionChoice(); // call the encryption choice method


            String userInput2 = String.format("%st%sAES%s",
                    System.lineSeparator(),
                    System.lineSeparator(),
                    System.lineSeparator());
            ByteArrayInputStream bais2 = new ByteArrayInputStream(userInput2.getBytes());
            System.setIn(bais2);

            ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
            PrintStream printStream2 = new PrintStream(baos2);
            System.setOut(printStream2);

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
            String userInput = String.format("128%s",
                    System.lineSeparator());
            ByteArrayInputStream bais = new ByteArrayInputStream(userInput.getBytes());
            System.setIn(bais);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PrintStream printStream = new PrintStream(baos);
            System.setOut(printStream);

            int keySizeOutput = MainClient.keySizeChoice("AES"); // call the key size choice method


            String userInput2 = String.format("%s1%s1024%s",
                    System.lineSeparator(),
                    System.lineSeparator(),
                    System.lineSeparator());
            ByteArrayInputStream bais2 = new ByteArrayInputStream(userInput2.getBytes());
            System.setIn(bais2);

            ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
            PrintStream printStream2 = new PrintStream(baos2);
            System.setOut(printStream2);

            int keySizeOutput2 = MainClient.keySizeChoice("RSA");

            // checkout output
            assertAll(
                    () -> assertEquals(1024,keySizeOutput2),
                    () -> assertEquals(128,keySizeOutput),
                    () -> assertNotEquals(1,keySizeOutput2)
            );
        }
    }


}