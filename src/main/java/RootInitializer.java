import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;
import org.bouncycastle.tsp.cms.CMSTimeStampedDataGenerator;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.jetbrains.annotations.NotNull;

import javax.crypto.*;
import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

public class RootInitializer {
    private static KeyStore keyStore;
    private final static char[] keystorePassword="password_16556)('.-((-".toCharArray() ;
    private final static String keystoreFilePath = "C:\\Users\\Youness\\Documents\\kys.p12";
    protected final static String rootAlias="Genesis";
    protected final static char[] rootPasswordRaw="root00Passwo0ordR4awYC99_1656)('.-((-".toCharArray() ;
    protected final static String certSignerAlias="Voucher";
    protected final static char[] certSignerPassword="ISwearThisIsValid".toCharArray();
    public static void initAll() {
        File keystoreFile = new File(keystoreFilePath);
        if(keystoreFile.exists())
            return;
        try {
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, keystorePassword);
            keyStore.store(new FileOutputStream(keystoreFile), keystorePassword);
            System.out.println("Keystore created at " + keystoreFilePath);
            generateRootCert();

            X509CertificatesGenerator.generateCert(RootInitializer.rootAlias, RootInitializer.rootPasswordRaw,
                    "cn=AC Global eStamp,o=EURAFRIC INFORMATION,c=MA", 5*24*365,
                    certSignerAlias, certSignerPassword, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign));

            X509CertificatesGenerator.generateCert(RootInitializer.rootAlias, RootInitializer.rootPasswordRaw,
                    "cn=AC Global Time Stamp,o=EURAFRIC INFORMATION,c=MA", 5*24*365,
                    TimeStampAuthority.timeStampAlias, TimeStampAuthority.timeStampPassword, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));

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

    private static Certificate[] getRootCert(){
        Certificate[] c;
        try {
            c = getKeyStore().getCertificateChain(rootAlias);
            return c;
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }
    protected static Key getRootCertKey(){
        try {
            return getKeyStore().getKey(rootAlias, rootPasswordRaw);
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

            CRL.generateCRL(rootKeyPair.getPrivate());


            BigInteger rootSerialNumber = secretKeyToSerialNumber(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
            //System.out.println(rootSerialNumber);
            Date rootStartDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000); //yesterday
            Date rootEndDate = new Date(System.currentTimeMillis() + 5L * 365 * 24 * 60 * 60 * 1000); // 10 years after today
            X500Principal rootIssuer  = new X500Principal("cn=EAI Root CA,o=EURAFRIC INFORMATION,c=MA");
            X500Principal rootSubject = new X500Principal("cn=EAI Root CA,o=EURAFRIC INFORMATION,c=MA");
            X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(
                    rootIssuer, rootSerialNumber, rootStartDate, rootEndDate, rootSubject, rootKeyPair.getPublic());//no java.util.Locale localDate
            rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));//isCA = true
            rootCertBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

            //rootCertBuilder.addExtension(Extension.subjectAlternativeName, false, new GeneralName(GeneralName.dNSName, "localhost")); ???
            ASN1ObjectIdentifier cRLDistributionPoints = new ASN1ObjectIdentifier("2.5.29.31");
            DistributionPoint[] points = new DistributionPoint[1];
            points[0] = new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, CRL.crlURI))),null, null);
            rootCertBuilder.addExtension(cRLDistributionPoints, true, new CRLDistPoint(points));


            // Create the Authority Key Identifier extension
            SubjectPublicKeyInfo caPublicKeyInfo = SubjectPublicKeyInfo.getInstance(rootKeyPair.getPublic().getEncoded());
            AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier(caPublicKeyInfo);

            // Add the extension to the certificate builder
            rootCertBuilder.addExtension(
                    org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier,
                    false,
                    authorityKeyIdentifier
            );

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

    protected static void insertIntoKeyStore(String alias, PrivateKey privateKey, Certificate[] chain, char[] password)
            throws Exception {
        KeyStore keyStore=getKeyStore();
        keyStore.setKeyEntry(alias, privateKey, password, chain);
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
