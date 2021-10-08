package cryptoproject;

import java.io.*;
import java.security.spec.*;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;

public class CryptoProject {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {
        // TODO code application logic here
        Scanner sc = new Scanner(System.in);
        int input;
        String fileName;
        String keyFileName;
        boolean running = true;
        while (running) {
            System.out.println(String.format("%-20s", "A SYMMETRIC CRYPTO SYSTEM"));
            System.out.println("==========================================================================");
            System.out.println("MAIN MENU");
            System.out.println("----------------------");

            System.out.println("1. Encrypt" + "\n" + "2. Decrypt " + "\n" + "3. Exit");
            System.out.println("----------------------");
            System.out.print("Enter your choice: ");
            input = sc.nextInt();
            switch (input) {
                // encrypt using AES/DES
                case 1: {
                    System.out.print("Type your choice: ");
                    System.out.println("(1) File (2) Folder");
                    String fifo = sc.next();
                    if ("file".equals(fifo)) {
                        System.out.println("Enter Name: ");
                    }
                    fileName = sc.next();
                    System.out.print("Algorithm (AES, DES):");
                    String wrd2 = sc.next();
                    if ("AES".equals(wrd2)) {
                        System.out.println("Enter Key from 16 letter: ");
                        String key = sc.next();
                        System.out.println("---------------");
                        encryptedFile(key, fileName, "text.enc");

                    } else if ("DES".equals(wrd2)) {
                        System.out.println("Enter Key: ");
                        keyFileName = sc.next();
                        System.out.println("---------------");
                        writeKey(56, keyFileName, "DES");
                        encryptFile(fileName, keyFileName);

                    } else if ("folder".equals(fifo)) {
                        System.out.print("Algorithm (AES, DES):");
                        String wrd22 = sc.next();
                        if ("AES".equals(wrd22)) {
                            System.out.println("Enter Key from 16 letter: ");
                            System.out.println("---------------");
                            String keya = sc.next();
                            File file = new File("D:\\Files"); //change to the right path
                            File[] list = new File[10];
                            if (file.exists()) {
                            } else {
                                System.out.println("Directory Not Found");
                            }
                            int c = 0;
                            for (int i = 0; i < list.length; i++) {
                                c++;
                                System.out.println(list[i].getName());
                                System.out.println("-------------------------------------------------------------------");
                                try {
                                    String x;
                                    BufferedReader br = new BufferedReader(new FileReader("D:\\Files\\" + list[i].getName()));
                                    while ((x = br.readLine()) != null) {
                                        encryptedFile(keya, list[i].getAbsolutePath(), list[i].getAbsolutePath()); //AES done
                                    }
                                    br.close();
                                    System.out.println("-------------------------------------------------------------------");
                                } catch (Exception e) {
                                    System.out.println(e);
                                }
                            }

                        } else if ("DES".equals(wrd22)) {
                            System.out.println("Enter Key: ");
                            keyFileName = sc.next();
                            System.out.println("---------------");
                            File file = new File("D:\\Files"); //change to the right path
                            File[] list = new File[10];
                            if (file.exists()) {
                                list = file.listFiles();

                            } else {
                                System.out.println("Directory Not Found");
                            }
                            int c = 0;
                            for (File list1 : list) {
                                c++;
                                System.out.println(list1.getName());
                                try {
                                    String x;
                                    BufferedReader br = new BufferedReader(new FileReader("D:\\Files\\" + list1.getName()));
                                    while ((x = br.readLine()) != null) {
                                        writeKey(56,keyFileName,"DES");
                                        encryptFile(list1.getAbsolutePath(), keyFileName);
                                    }
                                    br.close();
                                    System.out.println("-------------------------------------------------------------------");
                                }catch (Exception e) {
                                    System.out.println(e);
                                }
                            }

                        }

                    }
                    break;
                }
                // Decrypt using AES/DES
                case 2: {
                    System.out.print("Type your choice: ");
                    System.out.println("(1) File (2) Folder");
                    String fifo = sc.next();
                    if ("file".equals(fifo)) {
                        System.out.println("Enter Name: ");
                        fileName = sc.next();
                        System.out.print("Algorithm (AES, DES):");
                        String wrd2 = sc.next();
                        if ("AES".equals(wrd2)) {
                            System.out.println("Enter Key from 16 letter: ");
                            String key = sc.next();
                            System.out.println("---------------");
                            decryptedFile(key, "text-encrypt.txt", "text-decrypt.txt");
                        } else if ("DES".equals(wrd2)) {
                            System.out.println("Enter Key: ");
                            keyFileName = sc.next();
                            readKey(keyFileName, "DES");
                            System.out.println("---------------");
                            decryptFile(fileName, keyFileName);
                        }
                    } else if ("folder".equals(fifo)) {
                        System.out.print("Algorithm (AES, DES):");
                        String wrd22 = sc.next();
                        if ("AES".equals(wrd22)) {
                            System.out.println("Enter Key from 16 letter: ");
                            System.out.println("---------------");
                            String keya = sc.next();
                            File file = new File("D:\\Files"); //change to the right path
                            File[] list = new File[10];
                            if (file.exists()) {
                            } else {
                                System.out.println("Directory Not Found");
                            }
                            int c = 0;
                            for (int i = 0; i < list.length; i++) {
                                c++;
                                System.out.println(list[i].getName());
                                System.out.println("-------------------------------------------------------------------");
                                try {
                                    String x;
                                    BufferedReader br = new BufferedReader(new FileReader("D:\\Files\\" + list[i].getName()));
                                    while ((x = br.readLine()) != null) {
                                        decryptedFile(keya, list[i].getAbsolutePath(), list[i].getAbsolutePath()); //AES done
                                    }
                                    br.close();
                                    System.out.println("-------------------------------------------------------------------");
                                } catch (Exception e) {
                                    System.out.println(e);
                                }
                            }

                        } else if ("DES".equals(wrd22)) {
                            System.out.println("Enter Key: ");
                            keyFileName = sc.next();
                            System.out.println("---------------");
                            File file = new File("D:\\Files");//change to the right path
                            File[] list = new File[10];
                            if (file.exists()) {
                                list = file.listFiles();

                            } else {
                                System.out.println("Directory Not Found");
                            }
                            int c = 0;
                            for (File list1 : list) {
                                c++;
                                System.out.println(list1.getName());
                                try {
                                    String x;
                                    BufferedReader br = new BufferedReader(new FileReader("D:\\Files\\" + list1.getName()));
                                    while ((x = br.readLine()) != null) {
                                        readKey(keyFileName, "DES");
                                        decryptFile(list1.getAbsolutePath(), keyFileName);
                                    }
                                    br.close();
                                    System.out.println("-------------------------------------------------------------------");
                                }catch (Exception e) {
                                    System.out.println(e);
                                }
                            }

                        }
                    }
                    break;
                }

                case 3:

                    running = false;

                    System.out.println("--------------------------------------------------------------------------");
            }
        }
    }
    // for DES algorithem

    private static void encryptFile(String fileName, String keyName) {
        String original = fileName;
        String encrypted = fileName;
        Cipher encrypt;
        byte[] initialization_vector = {22, 33, 11, 44, 55, 99, 66, 77};
        try {
            SecretKey secret_key = readKey(keyName, "DES");
            AlgorithmParameterSpec alogrithm_specs = new IvParameterSpec(initialization_vector);
            encrypt = Cipher.getInstance("DES/CBC/PKCS5Padding");
            encrypt.init(Cipher.ENCRYPT_MODE, secret_key, alogrithm_specs);
            encrypt(new FileInputStream(original), new FileOutputStream(encrypted), encrypt);
            System.out.println("Done! File " + fileName + " is encrypted using DES" + "\n" + "Output file is " + fileName + ".encrypted");

        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }

    private static void decryptFile(String fileName, String keyName) {
        String original = fileName;
        String encrypted = fileName ;
        Cipher decrypt;
        byte[] initialization_vector = {22, 33, 11, 44, 55, 99, 66, 77};
        try {
            SecretKey secret_key = readKey(keyName, "DES");
            AlgorithmParameterSpec alogrithm_specs = new IvParameterSpec(initialization_vector);

            decrypt = Cipher.getInstance("DES/CBC/PKCS5Padding");
            decrypt.init(Cipher.DECRYPT_MODE, secret_key, alogrithm_specs);
            decrypt(new FileInputStream(encrypted), new FileOutputStream(original), decrypt);
            System.out.println("Done! File " + fileName + " is decrypted using DES");
            System.out.println("Output file is " + fileName + ".decrypted");
        } catch (Exception e) {
            System.out.println(e.toString());
        }
    }

    private static void encrypt(InputStream input, OutputStream output, Cipher encrypt) throws IOException {
        output = new CipherOutputStream(output, encrypt);
        writeBytes(input, output);
    }

    private static void decrypt(InputStream input, OutputStream output, Cipher decrypt) throws IOException {

        input = new CipherInputStream(input, decrypt);
        writeBytes(input, output);
    }

    private static void writeBytes(InputStream input, OutputStream output) throws IOException {
        byte[] writeBuffer = new byte[1024];
        int readBytes = 0;
        while ((readBytes = input.read(writeBuffer)) >= 0) {
            output.write(writeBuffer, 0, readBytes);
        }
        output.close();
        input.close();
    }

    private static void writeKey(int keySize, String output, String algorithm) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(algorithm);
        kg.init(keySize);

        SecretKey ky = kg.generateKey();
        byte[] kb;
        try (FileOutputStream fos = new FileOutputStream(output)) {
            kb = ky.getEncoded();
            fos.write(kb);
        }
    }

    private static SecretKey readKey(String input, String algorithm) throws Exception {
        FileInputStream fis = new FileInputStream(input);
        int kl = fis.available();
        byte[] kb = new byte[kl];
        fis.read(kb);
        fis.close();
        KeySpec ks = null;
        SecretKey ky = null;
        SecretKeyFactory kf = null;
        if (algorithm.equalsIgnoreCase("DES")) {
            ks = new DESKeySpec(kb);
            kf = SecretKeyFactory.getInstance("DES");
            ky = kf.generateSecret(ks);
        } else if (algorithm.equalsIgnoreCase("DESede")) {
            ks = new DESedeKeySpec(kb);
            kf = SecretKeyFactory.getInstance("DESede");
            ky = kf.generateSecret(ks);
        } else {
            ks = new SecretKeySpec(kb, algorithm);
            ky = new SecretKeySpec(kb, algorithm);
        }
        return ky;
    }

    // For AES algorithem
    public static void encryptedFile(String secretKey, String FileInputStream, String FileOutputStream)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException,
            IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        File fileInput = new File(FileInputStream);
        FileInputStream inputStream = new FileInputStream(fileInput);
        byte[] inputBytes = new byte[(int) fileInput.length()];
        inputStream.read(inputBytes);

        byte[] outputBytes = cipher.doFinal(inputBytes);

        File fileEncryptOut = new File(FileOutputStream);
        FileOutputStream outputStream = new FileOutputStream(fileEncryptOut);
        outputStream.write(outputBytes);

        inputStream.close();
        outputStream.close();

        System.out.println("Done! File " + FileOutputStream + " is incrypted using AES");
        System.out.println("Output file is " + FileOutputStream);

    }

    public static void decryptedFile(String secretKey, String FileInputStream, String FileOutputStream)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException,
            IllegalBlockSizeException, BadPaddingException {
        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);

        File fileInput = new File(FileInputStream);
        FileInputStream inputStream = new FileInputStream(fileInput);
        byte[] inputBytes = new byte[(int) fileInput.length()];
        inputStream.read(inputBytes);

        byte[] outputBytes = cipher.doFinal(inputBytes);

        File fileEncryptOut = new File(FileOutputStream);
        FileOutputStream outputStream = new FileOutputStream(fileEncryptOut);
        outputStream.write(outputBytes);

        inputStream.close();
        outputStream.close();

        System.out.println("Done! File " + FileOutputStream + " is decrypted using AES");
        System.out.println("Output file is " + FileOutputStream);
    }
}
