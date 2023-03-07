import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jetbrains.annotations.NotNull;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Locale;

public class RootCertHandler {
    private static KeyStore keyStore;
    protected final static String crlPath="C:\\Users\\Youness\\Documents\\crl.crl";
    protected final static String crlURI="file:///C:/Users/Youness/Documents/crl.crl";
    protected final static String rootAlias="Genesis";
    protected final static String rootPasswordRaw="root00Passwo0ordR4awYC99_1656)('.-((-" ;
    private final static char[] keystorePassword="password_16556)('.-((-".toCharArray() ;
    private final static String keystoreFilePath = "C:\\Users\\Youness\\Documents\\kys.p12";
    private static Certificate[] getRootCert(){
        Certificate[] c;
        try {
            c = getKeyStore().getCertificateChain(rootAlias);
            return c;
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }
    private static Key getRootCertKey(){
        try {
            return getKeyStore().getKey(rootAlias, rootPasswordRaw.toCharArray());
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    private static void generateRootCert(){
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // Generate a key pair for the root certificate authority
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");

            keyPairGenerator.initialize(2048, new SecureRandom());
            KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();

            // Generate the root certificate authority
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // for example
            SecretKey secretKey = keyGen.generateKey();
            //String secretKey = "UmLMeGR1sWeuxknWbMyFJQ==";
            //System.out.println(Base64.getEncoder().encodeToString(secretKey.getEncoded()));

            generateCRL(rootKeyPair.getPrivate());


            BigInteger rootSerialNumber = secretKeyToSerialNumber(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
            //System.out.println(rootSerialNumber);
            Date rootStartDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000); //yesterday
            Date rootEndDate = new Date(System.currentTimeMillis() + 10L * 365 * 24 * 60 * 60 * 1000); // 10 years after today
            X500Principal rootIssuer  = new X500Principal("cn=EAI Root CA\no=EURAFRIC INFORMATION\nc=MA");
            X500Principal rootSubject = new X500Principal("cn=EAI Root CA\no=EURAFRIC INFORMATION\nc=MA");
            X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(
                    rootIssuer, rootSerialNumber, rootStartDate, rootEndDate, rootSubject, rootKeyPair.getPublic());//no java.util.Locale localDate
            rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));//isCA = true
            rootCertBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

            //rootCertBuilder.addExtension(Extension.subjectAlternativeName, false, new GeneralName(GeneralName.dNSName, "localhost")); ???
            ASN1ObjectIdentifier cRLDistributionPoints = new ASN1ObjectIdentifier("2.5.29.31");
            DistributionPoint[] points = new DistributionPoint[1];
            points[0] = new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, RootCertHandler.crlURI))),null, null);
            rootCertBuilder.addExtension(cRLDistributionPoints, true, new CRLDistPoint(points));

            ContentSigner rootCertSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(rootKeyPair.getPrivate());
            X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertSigner);
            X509Certificate rootCert = new JcaX509CertificateConverter().getCertificate(rootCertHolder);

            // Save the root certificate authority to file

            insertIntoKeyStore(rootAlias, rootKeyPair.getPrivate(), new Certificate[] {rootCert}, rootPasswordRaw);

            /*FileOutputStream rootCertOut = new FileOutputStream("root.cer");
            rootCertOut.write(rootCert.getEncoded());
            rootCertOut.close();*/
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }  catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (CertIOException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    protected static void generateCRL(PrivateKey pk) throws OperatorCreationException, CRLException, IOException {
        X509v2CRLBuilder crlB= new X509v2CRLBuilder(new X500Name("cn=EAI Root CA\no=EURAFRIC INFORMATION\nc=MA"), new Date(System.currentTimeMillis()), new Locale("fr","MA"));
        X509CRLHolder crlH = crlB.build(new JcaContentSignerBuilder("SHA256withRSA").build(pk));
        X509CRL crl = new JcaX509CRLConverter().getCRL(crlH);
        File crlFile = new File(crlPath);
        if (!crlFile.getParentFile().exists()) {
            crlFile.getParentFile().mkdirs();
        }
        FileOutputStream fos = new FileOutputStream(crlFile);
        byte[] crlBytes = crl.getEncoded();
        fos.write(crlBytes);
        fos.close();
    }

    protected static void addToCRL(BigInteger serialNumber, Date revocationDate, int reason){
        try {
            FileInputStream fis = new FileInputStream(crlPath);
            X509CRLHolder crl = new X509CRLHolder(fis);
            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(crl);
            crlBuilder.addCRLEntry(serialNumber, revocationDate, reason);
            X509CRLHolder crlH = crlBuilder.build(new JcaContentSignerBuilder("SHA256withRSA").build((PrivateKey) getRootCertKey()));
            X509CRL x509crl = new JcaX509CRLConverter().getCRL(crlH);
            fis.close();
            FileOutputStream fos = new FileOutputStream("crlPath");
            byte[] crlBytes = x509crl.getEncoded();
            fos.write(crlBytes);
            fos.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (CRLException e) {
            throw new RuntimeException(e);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }
    }
    protected static void insertIntoKeyStore(String alias, PrivateKey privateKey, Certificate[] chain, String password)
            throws Exception {
        KeyStore keyStore=getKeyStore();
        keyStore.setKeyEntry(alias, privateKey, password.toCharArray(), chain);
        saveKeystore(keyStore);
    }
    @NotNull
    protected static KeyStore getKeyStore() {
        if(keyStore==null){

            File keystoreFile = new File(keystoreFilePath);

            try {
                keyStore = KeyStore.getInstance("PKCS12");
                if (keystoreFile.exists()) {
                    keyStore.load(new FileInputStream(keystoreFile), keystorePassword);
                    return keyStore;
                } else {
                    try {
                        keyStore.load(null, keystorePassword);
                        keyStore.store(new FileOutputStream(keystoreFile), keystorePassword);
                        System.out.println("Keystore created at " + keystoreFilePath);
                        generateRootCert();
                        return keyStore;
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } catch (CertificateException e) {
                throw new RuntimeException(e);
            } catch (KeyStoreException e) {
                throw new RuntimeException(e);
            }
        }
        return keyStore;
    }
    protected static void saveKeystore(@NotNull KeyStore keystore){
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(keystoreFilePath);
            keystore.store(fos, keystorePassword);
            fos.close();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }
    @NotNull
    protected static BigInteger secretKeyToSerialNumber(@NotNull String secretKey){
        byte[] decoded = Base64.getDecoder().decode(secretKey);
        return new BigInteger(1, decoded);
    }
    /*@NotNull
    protected static String serialNumberToSecretKey(@NotNull BigInteger serialNumber){
        byte[] bytes = serialNumber.toByteArray();
        return Base64.getEncoder().encodeToString(bytes);
    }
    protected static SecretKey getSecretKey(String alias) throws KeyStoreException {
        X509Certificate cert = (X509Certificate)RootCertHandler.getKeyStore().getCertificateChain(alias)[0];
        byte[] decodedKey = serialNumberToSecretKey(cert.getSerialNumber()).getBytes();
        SecretKey secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        return secretKey;
    }*/
}
