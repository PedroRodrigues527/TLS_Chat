import org.junit.jupiter.api.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
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

        @DisplayName ("Test key exchange choice")
        @Test
        public void testKeyExchangeChoice() {
            String userInput = String.format("%s",
                    System.lineSeparator());
            detectInputOutput(userInput);

            String keyExchangeOutput = MainClient.keyExchangeChoice(); // call the key exchange choice method


            String userInput2 = String.format("DH%s",
                    System.lineSeparator());
            detectInputOutput(userInput2);

            String keyExchangeOutput2 = MainClient.keyExchangeChoice();

            // checkout output
            assertAll(
                    () -> assertEquals("DH",keyExchangeOutput2),
                    () -> assertEquals("none",keyExchangeOutput),
                    () -> assertNotEquals("ECDH",keyExchangeOutput2)
            );
        }
    }

    @Nested
    @DisplayName("DHNumberGenerator Tests")
    class DHNumberGeneratorTests
    {
        @DisplayName ("Test DHNumbers")
        @Test
        public void testDHNumber() {
            int primeNumber, primitiveRoot;
            do {
                primeNumber = DHNumberGenerator.generateP();
                primitiveRoot = DHNumberGenerator.generateG(primeNumber);
            } while(primitiveRoot == -1);

            int G2 = DHNumberGenerator.generateG(4);
            int G3 = DHNumberGenerator.generateG(2);
            int G4 = DHNumberGenerator.generateG(277);
            int finalPrimeNumber = primeNumber;
            int finalPrimitiveRoot = primitiveRoot;

            assertAll(
                    () -> assertTrue(DHNumberGenerator.isPrime(finalPrimeNumber)),
                    () -> assertFalse(DHNumberGenerator.isPrime(4)),
                    () -> assertFalse(DHNumberGenerator.isPrime(50)),
                    () -> assertFalse(DHNumberGenerator.isPrime(1000)),
                    () -> assertFalse(DHNumberGenerator.isPrime(1)),
                    () -> assertFalse(DHNumberGenerator.isPrime(25)),
                    () -> assertNotEquals(-1, finalPrimitiveRoot),
                    () -> assertEquals(-1, G2),
                    () -> assertEquals(-1, G3),
                    () -> assertNotEquals(-1, G4)
            );
        }
    }

    @Nested
    @DisplayName("DiffieHellman Tests")
    class DiffieHellmanTests
    {
        @DisplayName ("Test DiffieHellman")
        @Test
        public void testDH() {

            int P = 13, G = 6;
            int PRa = 5, PRb = 4;
            BigInteger PUa = DiffieHellman.generatePublicKey(BigInteger.valueOf(G), BigInteger.valueOf(P), BigInteger.valueOf(PRa));
            BigInteger PUb = DiffieHellman.generatePublicKey(BigInteger.valueOf(G), BigInteger.valueOf(P), BigInteger.valueOf(PRb));

            BigInteger SKa = DiffieHellman.generateSecretKey(BigInteger.valueOf(P), PUb, BigInteger.valueOf(PRa));
            BigInteger SKb = DiffieHellman.generateSecretKey(BigInteger.valueOf(P), PUa, BigInteger.valueOf(PRb));

            assertAll(
                    () -> assertEquals(SKa, SKb)
            );
        }
    }

    @Nested
    @DisplayName("ECDiffieHellman Tests")
    class ECDiffieHellmanTests
    {
        @DisplayName ("Test ECDiffieHellman")
        @Test
        public void testECDH() throws NoSuchAlgorithmException, InvalidKeyException {
            ECDiffieHellman ecdh = new ECDiffieHellman();
            KeyPair keyPair1 = ecdh.generateKeyPair();
            KeyPair keyPair2 = ecdh.generateKeyPair();

            byte[] secretKey1 = ecdh.getSecretKey(ecdh.getPrivateKey(keyPair1), ecdh.getPublicKey(keyPair2));
            byte[] secretKey2 = ecdh.getSecretKey(ecdh.getPrivateKey(keyPair2), ecdh.getPublicKey(keyPair1));

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] bkey1 = Arrays.copyOf(
                    sha256.digest(secretKey1), 16);
            byte[] bkey2 = Arrays.copyOf(
                    sha256.digest(secretKey2), 16);
            SecretKey desSpec1 = new SecretKeySpec(bkey1, "AES");
            SecretKey desSpec2 = new SecretKeySpec(bkey2, "AES");
            String key1String = Base64.getEncoder().encodeToString(desSpec1.getEncoded());
            String key2String = Base64.getEncoder().encodeToString(desSpec2.getEncoded());

            assertAll(
                    () -> assertEquals(key1String, key2String)
            );
        }
    }

    @Nested
    @DisplayName("HMac Tests")
    class HMacTests
    {
        @DisplayName ("Test HMac")
        @Test
        public void testHMac()
                throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
            String hmacSHA256Algorithm = "HmacSHA256";
            String data = "baeldung";
            String key = "123456";

            byte[] result = HMac.hmacWithJava(hmacSHA256Algorithm, data, key);
            String resultString = new String(result);

            SymmetricAlgorithm sa = new SymmetricAlgorithm();
            String algorithm = "AES";
            String secretKey = sa.generateKey(128, algorithm);
            byte[] encryptedMessage = SymmetricAlgorithm.encrypt(data.getBytes(), secretKey, algorithm);
            byte[] decryptedMessage = SymmetricAlgorithm.decrypt(encryptedMessage, secretKey, algorithm);
            String messageOutput = new String(decryptedMessage);

            byte[] result2 = HMac.hmacWithJava(hmacSHA256Algorithm, messageOutput, key);
            String resultString2 = new String(result2);

            assertEquals(resultString2, resultString);
        }
    }

    @Nested
    @DisplayName("RSA Tests")
    class RSATests
    {
        @DisplayName ("Test RSA")
        @Test
        public void testRSA() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
            RSA rsa = new RSA();
            ArrayList<Object> keyPair1 = rsa.generateKeyPair(1024);
            ArrayList<Object> keyPair2 = rsa.generateKeyPair(1024);

            PublicKey publicKey1 = (PublicKey) keyPair1.get(1);
            PublicKey publicKey2 = (PublicKey) keyPair2.get(1);
            PrivateKey privateKey1 = (PrivateKey) keyPair1.get(0);
            PrivateKey privateKey2 = (PrivateKey) keyPair2.get(0);

            String message = "This is a test message.";

            byte[] messageEncrypted1 = RSA.encrypt(message.getBytes(), publicKey2);
            byte[] messageEncrypted2 = RSA.encrypt(message.getBytes(), publicKey1);

            byte[] messageDecrypted1 = RSA.decrypt(messageEncrypted1, privateKey2);
            byte[] messageDecrypted2 = RSA.decrypt(messageEncrypted2, privateKey1);

            String message1 = new String(messageDecrypted1);
            String message2 = new String(messageDecrypted2);

            assertAll(
                    () -> assertEquals(message, message1),
                    () -> assertEquals(message, message2)
            );
        }
    }

    @Nested
    @DisplayName("SymmetricAlgorithm Tests")
    class SymmetricAlgorithmTests
    {
        @DisplayName ("Test SymmetricAlgorithm")
        @Test
        public void testSymmetricAlgorithm() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeyException {
            SymmetricAlgorithm sa = new SymmetricAlgorithm();
            String message = "This is a test message.";
            String message2 = "QWERTYUIOPASDFG";
            String algorithm = "AES";

            String secretKey = sa.generateKey(128, algorithm);

            byte[] encryptedMessage = SymmetricAlgorithm.encrypt(message.getBytes(), secretKey, algorithm);
            byte[] decryptedMessage = SymmetricAlgorithm.decrypt(encryptedMessage, secretKey, algorithm);
            String messageOutput = new String(decryptedMessage);

            byte[] encryptedMessage1 = SymmetricAlgorithm.encrypt(message2.getBytes(), secretKey, algorithm);
            byte[] decryptedMessage1 = SymmetricAlgorithm.decrypt(encryptedMessage1, secretKey, algorithm);
            String messageOutput1 = new String(decryptedMessage1);

            assertAll(
                    () -> assertEquals(message, messageOutput),
                    () -> assertEquals(message2, messageOutput1)
            );
        }
    }

    @Nested
    @DisplayName("Client Test")
    class ClientTests
    {

        @DisplayName ("Test client")
        @Test
        public void testClient() throws Exception {
            Client client1 = new Client( "127.0.0.1" , 8000 , "user1", "AES", 256, "MD5", "DH" );
            Client client2 = new Client( "127.0.0.1" , 8000 , "user2", "AES", 256, "SHA256", "ECDH" );
            Client client3 = new Client( "127.0.0.1" , 8000 , "user3", "AES", 256, "none", "none" );
            Client client4 = new Client( "127.0.0.1" , 8000 , "user4", "DES", 56, "MD5", "DH" );
            Client client5 = new Client( "127.0.0.1" , 8000 , "user5", "DES", 56, "SHA512", "ECDH" );
            Client client6 = new Client( "127.0.0.1" , 8000 , "user6", "DES", 56, "none", "none" );
            Client client7 = new Client( "127.0.0.1" , 8000 , "user7", "TripleDES", 3*56, "MD5", "DH" );
            Client client8 = new Client( "127.0.0.1" , 8000 , "user8", "TripleDES", 3*56, "SHA512", "ECDH" );
            Client client9 = new Client( "127.0.0.1" , 8000 , "user9", "TripleDES", 3*56, "none", "none" );
            Client client10 = new Client( "127.0.0.1" , 8000 , "user10", "RSA", 1024, "none", "none" );
            Client client11 = new Client( "127.0.0.1" , 8000 , "user11", "RSA", 2048, "SHA256", "none" );

            // checkout values
            assertAll(
                    () -> assertEquals("user1",client1.getUserName()),
                    () -> assertEquals("AES",client1.getEncryptionUser()),
                    () -> assertEquals(256,client1.getKeySizeUser()),
                    () -> assertEquals("MD5",client1.getHashUser()),
                    () -> assertEquals("DH",client1.getKeyExchangeUser())
            );
        }

    }

    @Nested
    @DisplayName("Message Test")
    class MessageTests
    {

        @BeforeEach
        void setUp() throws IOException {
            MainServer.main(new String[0]);
        }

        @DisplayName ("Test messages sent and received")
        @Test
        public void testMessages() throws Exception {
            /*InputStream sysInBackup = System.in;

            Client client1 = new Client( "127.0.0.1" , 8000 , "user1", "AES", 256, "SHA256", "none" );
            Client client2 = new Client( "127.0.0.1" , 8000 , "user2", "AES", 128, "none", "none" );
            //Client client3 = new Client( "127.0.0.1" , 8000 , "user3", "DES", 56, "MD5", "none" );
            //Client client4 = new Client( "127.0.0.1" , 8000 , "user4", "DES", 56, "none", "none" );
            //Client client5 = new Client( "127.0.0.1" , 8000 , "user5", "TripleDES", 3*56, "SHA512", "none" );
            //Client client6 = new Client( "127.0.0.1" , 8000 , "user6", "TripleDES", 3*56, "none", "none" );
            Client client7 = new Client( "127.0.0.1" , 8000 , "user7", "RSA", 1024, "none", "none" );
            Client client8 = new Client( "127.0.0.1" , 8000 , "user8", "RSA", 2048, "SHA256", "none" );

            String userInput = String.format("Hi%sExit%s",
                    System.lineSeparator(),
                    System.lineSeparator());
            detectInputOutput(userInput);

            client2.readMessages();
            client1.sendMessages();

            System.setIn(sysInBackup);*/

            // checkout values
            /*assertAll(
                    () -> assertEquals(userName1,client1.getUserName()),
                    () -> assertEquals(encryptionUser1,client1.getEncryptionUser()),
                    () -> assertEquals(keyUserSize1,client1.getKeySizeUser()),
                    () -> assertEquals(hashUser1,client1.getHashUser()),
                    () -> assertEquals(keyExchangeUser1,client1.getKeyExchangeUser())
            );*/
        }

    }
}