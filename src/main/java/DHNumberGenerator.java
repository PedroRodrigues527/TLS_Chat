import java.util.*;

/**
 * Class responsible for the methods that involve the generations of prime numbers
 */
//FONTE: https://www.geeksforgeeks.org/primitive-root-of-a-prime-number-n-modulo-n/
public class DHNumberGenerator {

    /**
     * Method responsible for the generation of the Prime numbers
     *
     * @return
     */
    //FONTE: https://www.baeldung.com/java-generate-prime-numbers
    public static int generateP() {
        int n = 300;
        boolean[] prime = new boolean[n + 1];
        Arrays.fill(prime, true);
        for (int p = 2; p * p <= n; p++) {
            if (prime[p]) {
                for (int i = p * 2; i <= n; i += p) {
                    prime[i] = false;
                }
            }
        }
        List<Integer> primeNumbers = new LinkedList<>();
        for (int i = 2; i <= n; i++) {
            if (prime[i]) {
                primeNumbers.add(i);
            }
        }

        Random rand = new Random();
        return primeNumbers.get(rand.nextInt(primeNumbers.size()));
    }

    /**
     * Method responsible for the verification if the number is Prime or not, will return a boolean.
     *
     * @param n
     * @return
     */
    // Returns true if n is prime
    public static boolean isPrime(int n)
    {
        // Corner cases
        if (n <= 1)
        {
            return false;
        }
        if (n <= 3)
        {
            return true;
        }

        // This is checked so that we can skip
        // middle five numbers in below loop
        if (n % 2 == 0 || n % 3 == 0)
        {
            return false;
        }

        for (int i = 5; i * i <= n; i = i + 6)
        {
            if (n % i == 0 || n % (i + 2) == 0)
            {
                return false;
            }
        }

        return true;
    }

    /**
     * Method that complements the calculation of DiffieHellman
     *
     * @param x
     * @param y
     * @param p
     * @return
     */
    /* Iterative Function to calculate (x^n)%p in
    O(logy) */
    public static int power(int x, int y, int p)
    {
        int res = 1;     // Initialize result

        x = x % p; // Update x if it is more than or
        // equal to p

        while (y > 0)
        {
            // If y is odd, multiply x with result
            if (y % 2 == 1)
            {
                res = (res * x) % p;
            }

            // y must be even now
            y = y >> 1; // y = y/2
            x = (x * x) % p;
        }
        return res;
    }

    /**
     * Method that allows the finding of Prime factors.
     *
     * @param s
     * @param n
     */
    // Utility function to store prime factors of a number
    public static void findPrimefactors(HashSet<Integer> s, int n)
    {
        // Print the number of 2s that divide n
        while (n % 2 == 0)
        {
            s.add(2);
            n = n / 2;
        }

        // n must be odd at this point. So we can skip
        // one element (Note i = i +2)
        for (int i = 3; i <= Math.sqrt(n); i = i + 2)
        {
            // While i divides n, print i and divide n
            while (n % i == 0)
            {
                s.add(i);
                n = n / i;
            }
        }

        // This condition is to handle the case when
        // n is a prime number greater than 2
        if (n > 2)
        {
            s.add(n);
        }
    }

    /**
     * Method that creates a value of module to the primitive root of n with basis on DiffieHellman.
     *
     * @param n
     * @return
     */
    // Function to find smallest primitive root of n
    public static int generateG(int n)
    {
        HashSet<Integer> s = new HashSet<>();

        // Check if n is prime or not
        if (!isPrime(n))
        {
            return -1;
        }

        // Find value of Euler Totient function of n
        // Since n is a prime number, the value of Euler
        // Totient function is n-1 as there are n-1
        // relatively prime numbers.
        int phi = n - 1;

        // Find prime factors of phi and store in a set
        findPrimefactors(s, phi);

        // Check for every number from 2 to phi
        for (int r = 2; r <= phi; r++)
        {
            // Iterate through all prime factors of phi.
            // and check if we found a power with value 1
            boolean flag = false;
            for (Integer a : s)
            {

                // Check if r^((phi)/primefactors) mod n
                // is 1 or not
                if (power(r, phi / (a), n) == 1)
                {
                    flag = true;
                    break;
                }
            }

            // If there was no power with value 1.
            if (!flag)
            {
                return r;
            }
        }

        // If no primitive root found
        return -1;
    }
}
