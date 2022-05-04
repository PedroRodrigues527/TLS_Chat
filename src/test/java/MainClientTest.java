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
    @DisplayName("Server Requests tests")
    class usernameChoiceTest
    {

        private final InputStream systemIn = System.in;
        private final PrintStream systemOut = System.out;

        private ByteArrayInputStream testIn;
        private ByteArrayOutputStream testOut;

        @BeforeEach
        void setUp()
        {
            testOut = new ByteArrayOutputStream();
            System.setOut(new PrintStream(testOut));
        }

        private void provideInput(String data) {
            testIn = new ByteArrayInputStream(data.getBytes());
            System.setIn(testIn);
        }

        private String getOutput() {
            return testOut.toString();
        }

        @AfterEach
        public void restoreSystemInputOutput() {
            System.setIn(systemIn);
            System.setOut(systemOut);
        }

        @DisplayName ("Test username choice")
        @Test
        public void testUsername() {
            String userInput = String.format("User%s",
                    System.lineSeparator());
            ByteArrayInputStream bais = new ByteArrayInputStream(userInput.getBytes());
            System.setIn(bais);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PrintStream printStream = new PrintStream(baos);
            System.setOut(printStream);

            String userNameOutput = MainClient.usernameChoice(); // call the username method


            String userInput2 = String.format("%stest%s",
                    System.lineSeparator(),
                    System.lineSeparator());
            ByteArrayInputStream bais2 = new ByteArrayInputStream(userInput2.getBytes());
            System.setIn(bais2);

            ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
            PrintStream printStream2 = new PrintStream(baos2);
            System.setOut(printStream2);

            String userNameOutput2 = MainClient.usernameChoice(); // call the main method

            // checkout output
            assertAll(
                    () -> assertEquals("test",userNameOutput2),
                    () -> assertEquals("User",userNameOutput)
            );
        }
    }


}