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
import java.util.*;
import java.util.concurrent.locks.ReentrantLock;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Class responsible with the testing of multiple classes and methods
 */
class MainClientTest {
    /**
     * Class responsible for the different type of choices which utilizes mostly scanners
     */
    @Nested
    @DisplayName("Client choices' tests")
    class ChoiceTests
    {
        /**
         * Method responsible for the Input from the user regarding the Username
         */
        @DisplayName ("Test username choice")
        @Test
        public void testUsernameChoice() {
            String userInput = String.format("User%s",
                    System.lineSeparator());
            Scanner scanner = new Scanner(userInput);

            String userNameOutput = MainClient.usernameChoice(scanner); // call the username choice method

            String userInput2 = String.format("%stest%s",
                    System.lineSeparator(),
                    System.lineSeparator());
            scanner = new Scanner(userInput2);

            String userNameOutput2 = MainClient.usernameChoice(scanner);

            // checkout output
            assertAll(
                    () -> assertEquals("test",userNameOutput2),
                    () -> assertEquals("User",userNameOutput)
            );
        }

        /**
         * Method responsible for the choice of Input from the user regarding the Encryption Type.
         */
        @DisplayName ("Test encryption choice")
        @Test
        public void testEncryptionChoice() {
            String userInput = String.format("RSA%s",
                    System.lineSeparator());
            Scanner scanner = new Scanner(userInput);

            String encryptionOutput = MainClient.encryptionChoice(scanner); // call the encryption choice method


            String userInput2 = String.format("%st%sAES%s",
                    System.lineSeparator(),
                    System.lineSeparator(),
                    System.lineSeparator());
            scanner = new Scanner(userInput2);

            String encryptionOutput2 = MainClient.encryptionChoice(scanner);

            // checkout output
            assertAll(
                    () -> assertEquals("AES",encryptionOutput2),
                    () -> assertEquals("RSA",encryptionOutput),
                    () -> assertNotEquals("AES",encryptionOutput)
            );
        }

        /**
         * This method is responsible for the choice of the key size.
         */
        @DisplayName ("Test key size choice")
        @Test
        public void testKeySizeChoice() {
            String userInput = String.format("%s128%s",
                    System.lineSeparator(),
                    System.lineSeparator());
            Scanner scanner = new Scanner(userInput);

            int keySizeOutput = MainClient.keySizeChoice("AES", scanner); // call the key size choice method


            String userInput2 = String.format("%s1%s1024%s",
                    System.lineSeparator(),
                    System.lineSeparator(),
                    System.lineSeparator());
            scanner = new Scanner(userInput2);

            int keySizeOutput2 = MainClient.keySizeChoice("RSA", scanner);

            int keySizeOutput3 = MainClient.keySizeChoice("DES", scanner);

            int keySizeOutput4 = MainClient.keySizeChoice("TripleDES", scanner);

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

        /**
         * This method is responsible for the Hash choice by utilizing Scanners.
         */
        @DisplayName ("Test hash choice")
        @Test
        public void testHashChoice() {
            String userInput = String.format("%s",
                    System.lineSeparator());
            Scanner scanner = new Scanner(userInput);

            String hashOutput = MainClient.hashChoice(scanner); // call the hash choice method


            String userInput2 = String.format("SHA256%s",
                    System.lineSeparator());
            scanner = new Scanner(userInput2);

            String hashOutput2 = MainClient.hashChoice(scanner);

            // checkout output
            assertAll(
                    () -> assertEquals("SHA256",hashOutput2),
                    () -> assertEquals("none",hashOutput),
                    () -> assertNotEquals("SHA512",hashOutput2)
            );
        }

        /**
         * This method is responsible for the key Exchange choice
         */
        @DisplayName ("Test key exchange choice")
        @Test
        public void testKeyExchangeChoice() {
            String userInput = String.format("%s",
                    System.lineSeparator());
            Scanner scanner = new Scanner(userInput);

            String keyExchangeOutput = MainClient.keyExchangeChoice(scanner); // call the key exchange choice method


            String userInput2 = String.format("DH%s",
                    System.lineSeparator());
            scanner = new Scanner(userInput2);

            String keyExchangeOutput2 = MainClient.keyExchangeChoice(scanner);

            // checkout output
            assertAll(
                    () -> assertEquals("DH",keyExchangeOutput2),
                    () -> assertEquals("none",keyExchangeOutput),
                    () -> assertNotEquals("ECDH",keyExchangeOutput2)
            );
        }

        /**
         * Method responsible to test all the Client's Choices
         *
         * @throws Exception
         */
        @DisplayName ("Test all client choices")
        @Test
        public void testClientChoices() throws Exception {
            String userInput = String.format("userChoice%sAES%s128%sSHA256%sDH%sExit%s",
                    System.lineSeparator(),
                    System.lineSeparator(),
                    System.lineSeparator(),
                    System.lineSeparator(),
                    System.lineSeparator(),
                    System.lineSeparator());
            ByteArrayInputStream bais = new ByteArrayInputStream(userInput.getBytes());
            System.setIn(bais);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PrintStream printStream = new PrintStream(baos);
            System.setOut(printStream);

            MainClient.main(new String[0]); // call the MainClient main method


            String userInput2 = String.format("userChoice%sRSA%s1024%sSHA256%sExit%s",
                    System.lineSeparator(),
                    System.lineSeparator(),
                    System.lineSeparator(),
                    System.lineSeparator(),
                    System.lineSeparator());
            ByteArrayInputStream bais2 = new ByteArrayInputStream(userInput2.getBytes());
            System.setIn(bais2);

            ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
            PrintStream printStream2 = new PrintStream(baos2);
            System.setOut(printStream2);

            MainClient.main(new String[0]);

            // checkout output
            assertAll(
                    () -> assertTrue((baos.toString()).contains("Connecting to server...")),
                    () -> assertTrue((baos2.toString()).contains("Connecting to server..."))
            );
        }
    }

    /**
     * Class responsible for the DH Numbers generators tests
     */
    @Nested
    @DisplayName("DHNumberGenerator Tests")
    class DHNumberGeneratorTests
    {
        /**
         * Method responsible for the testing that involves the DH Numbers
         */
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

    /**
     * Class that will tests everything that involves the DiffielHellman and the key exchanges.
     */
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

    /**
     * Class that tests the involvement of the ECDiffielHellman
     */
    @Nested
    @DisplayName("ECDiffieHellman Tests")
    class ECDiffieHellmanTests
    {
        /**
         * ECDiffieHellman Method
         *
         * @throws NoSuchAlgorithmException
         * @throws InvalidKeyException
         */
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

    /**
     * This class will be responsible for the Hash based message authentication code
     */
    @Nested
    @DisplayName("HMac Tests")
    class HMacTests
    {
        /**
         * Method responsible for the specified HMAC test in order for both parties to communicate, and their connection to remain private.
         *
         * @throws NoSuchAlgorithmException
         * @throws InvalidKeyException
         * @throws NoSuchPaddingException
         * @throws IllegalBlockSizeException
         * @throws BadPaddingException
         * @throws IOException
         */
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

    /**
     * Class responsible for the RSA Protocol Testing
     */
    @Nested
    @DisplayName("RSA Tests")
    class RSATests
    {
        /**
         * Method responsible for the RSA testing, involving the utilization of both Public and Private Keys
         *
         * @throws NoSuchAlgorithmException
         * @throws NoSuchPaddingException
         * @throws IllegalBlockSizeException
         * @throws BadPaddingException
         * @throws InvalidKeyException
         */
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

    /**
     * This class is responsible for the Symmetric Algorithms Tests.
     */
    @Nested
    @DisplayName("SymmetricAlgorithm Tests")
    class SymmetricAlgorithmTests
    {
        /**
         * This method is responsible for the encryption and decryption of the specified messages, utilizing the Symmmetric Algorithms.
         *
         * @throws NoSuchAlgorithmException
         * @throws NoSuchPaddingException
         * @throws IllegalBlockSizeException
         * @throws BadPaddingException
         * @throws IOException
         * @throws InvalidKeyException
         */
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

    /**
     * This class will test everything that involves the Testing arround the Client-side Messages.
     */
    @Nested
    @DisplayName("Message Test")
    class MessageClientTests
    {

        @BeforeEach
        void setUp() throws IOException {
            MainServer.main(new String[0]);
        }

        /**
         * Method responsible for the Messages that involves the Clients.
         *
         * @throws Exception
         */
        @DisplayName ("Test messages sent and received")
        @Test
        public void testMessagesClient() throws Exception {

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

            Client client0 = new Client( "127.0.0.1" , 8000 , "muser0", "AES", 128, "none", "none" );

            client1.readMessages();
            client2.readMessages();
            client3.readMessages();
            client4.readMessages();
            client5.readMessages();
            client6.readMessages();
            client7.readMessages();
            client8.readMessages();
            client9.readMessages();
            client10.readMessages();
            client11.readMessages();

            String userInputtest = String.format("%s" +
                            "message%s" +
                            "@user1,@user2,@user3,@user4,@user5,@user6,@user7,@user8,@user9,@user10,@user11 specificMessage%s" +
                            "Exit%s",
                    System.lineSeparator(),
                    System.lineSeparator(),
                    System.lineSeparator(),
                    System.lineSeparator());

            Scanner scanner = new Scanner(userInputtest);
            ByteArrayOutputStream baos0 = new ByteArrayOutputStream();
            PrintStream printStream0 = new PrintStream(baos0);
            System.setOut(printStream0);
            client0.sendMessages(scanner);
            Thread.sleep(2000);
            scanner = new Scanner(userInputtest);
            ByteArrayOutputStream baos1 = new ByteArrayOutputStream();
            PrintStream printStream1 = new PrintStream(baos1);
            System.setOut(printStream1);
            client1.sendMessages(scanner);
            Thread.sleep(2000);
            scanner = new Scanner(userInputtest);
            ByteArrayOutputStream baos2 = new ByteArrayOutputStream();
            PrintStream printStream2 = new PrintStream(baos2);
            System.setOut(printStream2);
            client2.sendMessages(scanner);
            Thread.sleep(2000);
            scanner = new Scanner(userInputtest);
            ByteArrayOutputStream baos3 = new ByteArrayOutputStream();
            PrintStream printStream3 = new PrintStream(baos3);
            System.setOut(printStream3);
            client3.sendMessages(scanner);
            Thread.sleep(2000);
            scanner = new Scanner(userInputtest);
            ByteArrayOutputStream baos4 = new ByteArrayOutputStream();
            PrintStream printStream4 = new PrintStream(baos4);
            System.setOut(printStream4);
            client4.sendMessages(scanner);
            Thread.sleep(2000);
            scanner = new Scanner(userInputtest);
            ByteArrayOutputStream baos5 = new ByteArrayOutputStream();
            PrintStream printStream5 = new PrintStream(baos5);
            System.setOut(printStream5);
            client5.sendMessages(scanner);
            Thread.sleep(2000);
            scanner = new Scanner(userInputtest);
            ByteArrayOutputStream baos6 = new ByteArrayOutputStream();
            PrintStream printStream6 = new PrintStream(baos6);
            System.setOut(printStream6);
            client6.sendMessages(scanner);
            Thread.sleep(2000);
            scanner = new Scanner(userInputtest);
            ByteArrayOutputStream baos7 = new ByteArrayOutputStream();
            PrintStream printStream7 = new PrintStream(baos7);
            System.setOut(printStream7);
            client7.sendMessages(scanner);
            Thread.sleep(2000);
            scanner = new Scanner(userInputtest);
            ByteArrayOutputStream baos8 = new ByteArrayOutputStream();
            PrintStream printStream8 = new PrintStream(baos8);
            System.setOut(printStream8);
            client8.sendMessages(scanner);
            Thread.sleep(2000);
            scanner = new Scanner(userInputtest);
            ByteArrayOutputStream baos9 = new ByteArrayOutputStream();
            PrintStream printStream9 = new PrintStream(baos9);
            System.setOut(printStream9);
            client9.sendMessages(scanner);
            Thread.sleep(2000);
            scanner = new Scanner(userInputtest);
            ByteArrayOutputStream baos10 = new ByteArrayOutputStream();
            PrintStream printStream10 = new PrintStream(baos10);
            System.setOut(printStream10);
            client10.sendMessages(scanner);
            Thread.sleep(2000);
            scanner = new Scanner(userInputtest);
            ByteArrayOutputStream baos11 = new ByteArrayOutputStream();
            PrintStream printStream11 = new PrintStream(baos11);
            System.setOut(printStream11);
            client11.sendMessages(scanner);
            Thread.sleep(2000);

            // checkout values
            assertAll(
                    () -> assertEquals("muser0",client0.getUserName()),
                    () -> assertEquals("AES",client0.getEncryptionUser()),
                    () -> assertEquals(128,client0.getKeySizeUser()),
                    () -> assertEquals("none",client0.getHashUser()),
                    () -> assertEquals("none",client0.getKeyExchangeUser()),
                    () -> assertTrue(baos0.toString().contains("muser0: message")),
                    () -> assertTrue(baos0.toString().contains("muser0: @user1,@user2,@user3,@user4,@user5,@user6,@user7,@user8,@user9,@user10,@user11 specificMessage")),
                    () -> assertTrue(baos0.toString().contains("Exiting Chat..."))
            )
            ;assertAll(
                    () -> assertEquals("user1",client1.getUserName()),
                    () -> assertEquals("AES",client1.getEncryptionUser()),
                    () -> assertEquals(256,client1.getKeySizeUser()),
                    () -> assertEquals("MD5",client1.getHashUser()),
                    () -> assertEquals("DH",client1.getKeyExchangeUser()),
                    () -> assertTrue(baos1.toString().contains("user1: message")),
                    () -> assertTrue(baos1.toString().contains("user1: @user1,@user2,@user3,@user4,@user5,@user6,@user7,@user8,@user9,@user10,@user11 specificMessage")),
                    () -> assertTrue(baos1.toString().contains("Exiting Chat..."))
            )
            //*******
            ;assertAll(
                    () -> assertEquals("user2",client2.getUserName()),
                    () -> assertEquals("AES",client2.getEncryptionUser()),
                    () -> assertEquals(256,client2.getKeySizeUser()),
                    () -> assertEquals("SHA256",client2.getHashUser()),
                    () -> assertEquals("ECDH",client2.getKeyExchangeUser()),
                    () -> assertTrue(baos2.toString().contains("user2: message")),
                    () -> assertTrue(baos2.toString().contains("user2: @user1,@user2,@user3,@user4,@user5,@user6,@user7,@user8,@user9,@user10,@user11 specificMessage")),
                    () -> assertTrue(baos2.toString().contains("Exiting Chat..."))

            )
            ;assertAll(
                    () -> assertEquals("user3",client3.getUserName()),
                    () -> assertEquals("AES",client3.getEncryptionUser()),
                    () -> assertEquals(256,client3.getKeySizeUser()),
                    () -> assertEquals("none",client3.getHashUser()),
                    () -> assertEquals("none",client3.getKeyExchangeUser()),
                    () -> assertTrue(baos3.toString().contains("user3: message")),
                    () -> assertTrue(baos3.toString().contains("user3: @user1,@user2,@user3,@user4,@user5,@user6,@user7,@user8,@user9,@user10,@user11 specificMessage")),
                    () -> assertTrue(baos3.toString().contains("Exiting Chat..."))
            )
            ;assertAll(
                    () -> assertEquals("user4",client4.getUserName()),
                    () -> assertEquals("DES",client4.getEncryptionUser()),
                    () -> assertEquals(56,client4.getKeySizeUser()),
                    () -> assertEquals("MD5",client4.getHashUser()),
                    () -> assertEquals("DH",client4.getKeyExchangeUser()),
                    () -> assertTrue(baos4.toString().contains("user4: message")),
                    () -> assertTrue(baos4.toString().contains("user4: @user1,@user2,@user3,@user4,@user5,@user6,@user7,@user8,@user9,@user10,@user11 specificMessage")),
                    () -> assertTrue(baos4.toString().contains("Exiting Chat..."))
            )
            ;assertAll(
                    () -> assertEquals("user5",client5.getUserName()),
                    () -> assertEquals("DES",client5.getEncryptionUser()),
                    () -> assertEquals(56,client5.getKeySizeUser()),
                    () -> assertEquals("SHA512",client5.getHashUser()),
                    () -> assertEquals("ECDH",client5.getKeyExchangeUser()),
                    () -> assertTrue(baos5.toString().contains("user5: message")),
                    () -> assertTrue(baos5.toString().contains("user5: @user1,@user2,@user3,@user4,@user5,@user6,@user7,@user8,@user9,@user10,@user11 specificMessage")),
                    () -> assertTrue(baos5.toString().contains("Exiting Chat..."))
            )
            ;assertAll(
                    () -> assertEquals("user6",client6.getUserName()),
                    () -> assertEquals("DES",client6.getEncryptionUser()),
                    () -> assertEquals(56,client6.getKeySizeUser()),
                    () -> assertEquals("none",client6.getHashUser()),
                    () -> assertEquals("none",client6.getKeyExchangeUser()),
                    () -> assertTrue(baos6.toString().contains("user6: message")),
                    () -> assertTrue(baos6.toString().contains("user6: @user1,@user2,@user3,@user4,@user5,@user6,@user7,@user8,@user9,@user10,@user11 specificMessage")),
                    () -> assertTrue(baos6.toString().contains("Exiting Chat..."))
            )
            //6
            ;assertAll(
                    () -> assertEquals("user7",client7.getUserName()),
                    () -> assertEquals("TripleDES",client7.getEncryptionUser()),
                    () -> assertEquals(3*56,client7.getKeySizeUser()),
                    () -> assertEquals("MD5",client7.getHashUser()),
                    () -> assertEquals("DH",client7.getKeyExchangeUser()),
                    () -> assertTrue(baos7.toString().contains("user7: message")),
                    () -> assertTrue(baos7.toString().contains("user7: @user1,@user2,@user3,@user4,@user5,@user6,@user7,@user8,@user9,@user10,@user11 specificMessage")),
                    () -> assertTrue(baos7.toString().contains("Exiting Chat..."))
            )
            ;assertAll(
                    () -> assertEquals("user8",client8.getUserName()),
                    () -> assertEquals("TripleDES",client8.getEncryptionUser()),
                    () -> assertEquals(3*56,client8.getKeySizeUser()),
                    () -> assertEquals("SHA512",client8.getHashUser()),
                    () -> assertEquals("ECDH",client8.getKeyExchangeUser()),
                    () -> assertTrue(baos8.toString().contains("user8: message")),
                    () -> assertTrue(baos8.toString().contains("user8: @user1,@user2,@user3,@user4,@user5,@user6,@user7,@user8,@user9,@user10,@user11 specificMessage")),
                    () -> assertTrue(baos8.toString().contains("Exiting Chat..."))
            )
            ;assertAll(
                    () -> assertEquals("user9",client9.getUserName()),
                    () -> assertEquals("TripleDES",client9.getEncryptionUser()),
                    () -> assertEquals(3*56,client9.getKeySizeUser()),
                    () -> assertEquals("none",client9.getHashUser()),
                    () -> assertEquals("none",client9.getKeyExchangeUser()),
                    () -> assertTrue(baos9.toString().contains("user9: message")),
                    () -> assertTrue(baos9.toString().contains("user9: @user1,@user2,@user3,@user4,@user5,@user6,@user7,@user8,@user9,@user10,@user11 specificMessage")),
                    () -> assertTrue(baos9.toString().contains("Exiting Chat..."))
            )
            ;assertAll(
                    () -> assertEquals("user10",client10.getUserName()),
                    () -> assertEquals("RSA",client10.getEncryptionUser()),
                    () -> assertEquals(1024,client10.getKeySizeUser()),
                    () -> assertEquals("none",client10.getHashUser()),
                    () -> assertEquals("none",client10.getKeyExchangeUser()),
                    () -> assertTrue(baos10.toString().contains("user10: message")),
                    () -> assertTrue(baos10.toString().contains("user10: @user1,@user2,@user3,@user4,@user5,@user6,@user7,@user8,@user9,@user10,@user11 specificMessage")),
                    () -> assertTrue(baos10.toString().contains("Exiting Chat..."))
            )
            ;assertAll(
                    () -> assertEquals("user11",client11.getUserName()),
                    () -> assertEquals("RSA",client11.getEncryptionUser()),
                    () -> assertEquals(2048,client11.getKeySizeUser()),
                    () -> assertEquals("SHA256",client11.getHashUser()),
                    () -> assertEquals("none",client11.getKeyExchangeUser()),
                    () -> assertFalse(baos11.toString().contains("user11: message")),
                    () -> assertFalse(baos11.toString().contains("user11: @user1,@user2,@user3,@user4,@user5,@user6,@user7,@user8,@user9,@user10,@user11 specificMessage")),
                    () -> assertTrue(baos11.toString().contains("Exiting Chat..."))
            )
            ;assertAll(
                    () -> assertEquals("muser0",client0.getUserName()),
                    () -> assertEquals("AES",client0.getEncryptionUser()),
                    () -> assertEquals(128,client0.getKeySizeUser()),
                    () -> assertEquals("none",client0.getHashUser()),
                    () -> assertEquals("none",client0.getKeyExchangeUser()),
                    () -> assertTrue(baos0.toString().contains("muser0: message")),
                    () -> assertTrue(baos0.toString().contains("muser0: @user1,@user2,@user3,@user4,@user5,@user6,@user7,@user8,@user9,@user10,@user11 specificMessage")),
                    () -> assertTrue(baos0.toString().contains("Exiting Chat..."))
            );
        }

    }
}